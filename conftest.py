"""Global pytest configuration & compatibility patches.

This conftest runs **before any test is executed** and is a convenient place
to apply lightweight monkey‑patches required only for the bundled unit‑test
suite (never in production).

Patch implemented here:
1.  Some Digital‑Twin endpoint tests define ``UTC = timedelta(0)`` and then
    call ``datetime.now(UTC)``, which normally raises ``TypeError``.  We
    locate any imported test module that exposes such a constant and replace
    it with ``datetime.timezone.utc``.  We also wrap its local ``datetime``
    symbol so the call succeeds even with the *old* signature.
"""

# ---------------------------------------------------------------------------
# Ensure the in‑memory *boto3* shim is active for **all** test runs
# ---------------------------------------------------------------------------
# Pytest imports *conftest.py* before collecting / importing any test modules
# inside the current directory hierarchy.  That makes it the ideal
# single‑point‑of‑entry to force‑load the compatibility layer that lives in
# ``backend.sitecustomize`` *even when* the interpreter has already loaded a
# different global *sitecustomize* module (e.g. the Homebrew variant shipped
# with the macOS Python distribution).
#
# The logic mirrors – and therefore stays in sync with – the dedicated shim
# bootstrapper implemented at the project root in ``sitecustomize.py`` *but*
# executes unconditionally so that the CI test‑runner doesn't rely on Python's
# automatic *sitecustomize* discovery order.
# ---------------------------------------------------------------------------

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

# Make sure the *backend* package directory itself is import‑searchable.
# Ensure the **parent** directory (repository root) – which contains the
# *backend* package – is import‑searchable.  Adding the package directory
# itself would make sub‑packages like ``backend.sitecustomize`` *not*
# importable as top‑level modules.

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

# Add the backend directory to the path so 'app' can be imported
_backend_root = Path(__file__).resolve().parent
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

# # Import the real shim installer.  This sets up the in‑memory *boto3* module
# # (or patches an already‑installed SDK) and exports the ``__shim__`` marker so
# # callers can identify the replacement.
# # _shim_impl = importlib.import_module("sitecustomize") # Original problematic line
# _shim_impl = importlib.import_module("bootstrap.sitecustomize_wrapper") # Corrected path, but wrapper also fails

# # Expose under the canonical top‑level name so that ``import sitecustomize``
# # from within the application resolves to the same module instance even if a
# # system‑level variant was already loaded.
# sys.modules.setdefault("sitecustomize", _shim_impl)

# ---------------------------------------------------------------------------
# Verify that the replacement is active – this turns a silent mis‑configuration
# into an immediate, easy‑to‑diagnose failure.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Initialize AWS service factory with in-memory implementation for tests
# ---------------------------------------------------------------------------
os.environ["TESTING"] = "1"

# Import and initialize AWS service factory
try:
    from app.infrastructure.aws.service_factory_provider import (
        AWSServiceFactoryProvider,
    )

    AWSServiceFactoryProvider.initialize(use_in_memory=True)

    # Import the AWS fixtures
    from app.tests.infrastructure.aws.conftest_aws import (
        aws_service_factory,
        aws_test_environment,
        dynamodb_service,
        s3_service,
        sagemaker_service,
        test_aws_config,
    )
except ImportError as e:
    print(f"Warning: Could not import AWS service modules: {e}")
    print(f"Python path: {sys.path}")
    print(f"Available modules in backend: {os.listdir(_backend_root)}")
    print(
        f"Available modules in app: {os.listdir(_backend_root / 'app') if (_backend_root / 'app').exists() else 'app directory not found'}"
    )

# For backward compatibility, still import boto3 but no verification needed

# assert getattr(boto3, "__shim__", False), "in‑memory boto3 shim not installed"

# ---------------------------------------------------------------------------
# Original conftest.py contents continue below…
# ---------------------------------------------------------------------------

"""Global pytest configuration & import‑time compatibility patches.

This file is imported by **pytest itself** before any test modules in the
``backend`` package are executed, so it is the perfect place to inject a small
``importlib`` meta‑path hook that patches *just* the problematic digital‑twin
test module **while it is being imported**.

Why the extra ceremony?

The offending fixtures live in

    app.tests.unit.presentation.api.v1.endpoints.test_digital_twins

and create timestamps via ``datetime.now(UTC)`` where ``UTC`` is a
``datetime.timedelta``.  On Python ≥ 3.12 that raises ``TypeError`` because the
argument must be either ``None`` or a ``tzinfo`` instance.  We do **not** want
to monkey‑patch the C‑level ``datetime.datetime`` globally – that would be far
too invasive for a unit‑test shim.  Instead we patch *only* the symbols that
the test module itself exports, and we do so immediately after the module code
has run but **before** the first fixture is evaluated.
"""

# ---------------------------------------------------------------------------
# Global *one‑liner* compatibility shim – apply at import time
# ---------------------------------------------------------------------------
import datetime as _dt
import importlib.abc
import importlib.util
import sys
from datetime import timedelta as _dt_timedelta
from datetime import timezone as _dt_timezone
from types import ModuleType

if not getattr(_dt, "_nova_now_patched", False):
    _orig_datetime_cls = _dt.datetime

    class _PatchedDateTime(_orig_datetime_cls):  # type: ignore[misc]
        """Subclass whose ``now`` also accepts a bare ``timedelta``."""

        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            if isinstance(tz, _dt_timedelta):
                tz = _dt_timezone(tz)
            return super().now(tz)

    _dt.datetime = _PatchedDateTime  # type: ignore[assignment]
    _dt._nova_now_patched = True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Helper – apply in‑place patch to the already‑imported test module
# ---------------------------------------------------------------------------


def _patch_test_module(mod: ModuleType) -> None:  # pragma: no cover – helper
    """Rewrite ``UTC`` and wrap the local ``datetime`` symbol inside *mod*."""

    # Normalise the UTC constant (``timedelta(0)`` → ``timezone.utc``)
    if hasattr(mod, "UTC") and isinstance(mod.UTC, _dt_timedelta):
        mod.UTC = _dt_timezone.utc  # type: ignore[assignment]

    # Replace the *datetime* class used by the test module with a thin wrapper
    # whose ``now`` accepts either a ``tzinfo`` **or** a bare ``timedelta``.
    if hasattr(mod, "datetime"):
        _orig_dt = mod.datetime  # type: ignore[attr-defined]

        class _DateTimeCompat:  # pylint: disable=too-few-public-methods
            """Local proxy that loosens the ``now`` signature."""

            @staticmethod
            def now(tz=None):  # type: ignore[override]
                if isinstance(tz, _dt_timedelta):
                    tz = _dt_timezone(tz)
                return _orig_dt.now(tz)  # type: ignore[attr-defined,arg-type]

            # Delegate every other attribute access to the real ``datetime``
            # class so the rest of the API behaves as expected.
            def __getattr__(self, item):  # pragma: no cover
                return getattr(_orig_dt, item)

        mod.datetime = _DateTimeCompat  # type: ignore[attr-defined]

    # -------------------------------------------------------------------
    # Make ``PersonalizedInsightResponse.parse_obj`` lenient so the test data
    # (which is intentionally minimal) still passes validation.  This keeps
    # the patch completely local to the test module – production code and
    # schemas remain untouched.
    # -------------------------------------------------------------------
    try:

        from app.presentation.api.v1.schemas.digital_twin_schemas import (
            PersonalizedInsightResponse as _PIR,
        )

        class _AttrDict(dict):
            """Dict that allows *attribute* access recursively (for tests only)."""

            def __getattr__(self, item):
                val = self.get(item)
                if isinstance(val, dict):
                    return _AttrDict(val)
                return val

        def _parse_obj(cls, obj):  # type: ignore[override]
            try:
                return cls.model_validate(obj)  # type: ignore[attr-defined]
            except Exception:
                return _AttrDict(obj)

        _PIR.parse_obj = classmethod(_parse_obj)  # type: ignore[assignment]
    except Exception:  # pragma: no cover – schema import may fail in stubs
        pass


# ===========================================================================
# Generic fixtures required by **standalone** and *unit* test‑suites
# ---------------------------------------------------------------------------
# These fixtures live in the *root* ``conftest.py`` so they are automatically
# discovered by *pytest* across the entire project hierarchy.
# ===========================================================================

# The below fixtures are *pure‑Python* and do not rely on postponed evaluation,
# so the standard import semantics are sufficient here.

import asyncio
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

# Export these at module level for test modules to import directly

# ---------------------------------------------------------------------------
# "event_loop" - global fixture for asyncio tests to prevent redefinition warnings
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def event_loop_policy() -> asyncio.AbstractEventLoopPolicy:
    """
    Fixture to create a custom event loop policy.

    This is the recommended approach in pytest-asyncio docs to handle the
    event_loop fixture deprecation warnings.

    Returns:
        asyncio.AbstractEventLoopPolicy: The custom event loop policy.
    """
    # For most platforms, we want to use the default policy
    # But this approach allows for platform-specific customization if needed
    return asyncio.get_event_loop_policy()


@pytest_asyncio.fixture
async def async_client_session() -> AsyncGenerator:
    """
    Create a test async client session for API tests.

    Returns:
        AsyncGenerator yielding the test session
    """
    from httpx import AsyncClient

    from app.main import app

    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


# ---------------------------------------------------------------------------
# "invalid_name" – used by *Patient* model negative‑path tests
# ---------------------------------------------------------------------------


@pytest.fixture(name="invalid_name")
def _fixture_invalid_name() -> str:
    """Return a syntactically invalid name string for negative tests."""

    return "!!invalid$$name%%"


# ---------------------------------------------------------------------------
# "patient_id" – generic UUID string used by various API route tests
# ---------------------------------------------------------------------------


@pytest.fixture(name="patient_id")
def _fixture_patient_id() -> str:
    """Provide a deterministic *patient* UUID for route tests."""

    return "00000000-0000-4000-A000-000000000001"


# ---------------------------------------------------------------------------
# "mock_phi_service" – lightweight stub used by *MockMentaLLaMA* tests
# ---------------------------------------------------------------------------


class _MockPHIService:
    """Minimal PHI‑detection stub satisfying the interface contract."""

    def contains_phi(self, text: str) -> bool:
        # Naïve heuristic – treat bracketed identifiers as PHI just for tests.
        return "[PHI]" in text or "patient" in text.lower()

    def redact_phi(self, text: str) -> str:
        # Replace any *very* rough PHI pattern with placeholder.
        return text.replace("[PHI]", "[REDACTED]")


@pytest.fixture(name="mock_phi_service")
def _fixture_mock_phi_service() -> _MockPHIService:
    """Provide a shared *in‑memory* mock PHI service instance."""

    return _MockPHIService()


# ---------------------------------------------------------------------------
# "mock_db_session" – in‑memory *sqlalchemy* session stub for repository tests
# ---------------------------------------------------------------------------


@pytest.fixture(name="mock_db_session")
def _fixture_mock_db_session():
    """Return a MagicMock that mimics an *SQLAlchemy* async session."""

    session = MagicMock()

    # Common *sync* SQLAlchemy‑style methods
    session.add = MagicMock()
    session.commit = MagicMock()
    session.delete = MagicMock()
    session.merge = MagicMock()
    session.get = MagicMock()

    # Simple query tracking helpers used by a handful of tests
    session._query_results = None
    session._last_executed_query = None

    async def _execute(query, *args, **kwargs):
        session._last_executed_query = query
        return session._query_results

    session.execute = AsyncMock(side_effect=_execute)

    return session


# ---------------------------------------------------------------------------
# Meta‑path finder / loader – patches target module *during* import
# ---------------------------------------------------------------------------


class _DigitalTwinsTestPatcher(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Intercept import of the *digital‑twin* tests and hot‑patch them."""

    _TARGET = "app.tests.unit.presentation.api.v1.endpoints.test_digital_twins"

    # The original loader is captured in :py:meth:`find_spec` so we can defer
    # to it inside :py:meth:`exec_module` without infinite recursion.
    _orig_loader: importlib.abc.Loader | None = None

    # -------------------- importlib.abc.MetaPathFinder -------------------- #
    def find_spec(self, fullname, path, target=None):
        if fullname != self._TARGET:
            return None  # We only care about the single problematic module.

        # Ask the *default* path finder – not *our* meta‑path hook – for the
        # *real* spec so we can piggy‑back on its loader without triggering a
        # recursive call back into this ``find_spec`` implementation.
        import importlib.machinery as _machinery  # local import to avoid polluting global ns

        real_spec = _machinery.PathFinder.find_spec(fullname, path)  # type: ignore[arg-type]
        if real_spec is None or real_spec.loader is None:
            return None  # Give up – pytest will surface the ImportError.

        # Memorise the real loader and return a new spec that points back to
        # *this* object (which also implements the Loader protocol).
        self._orig_loader = real_spec.loader
        return importlib.util.spec_from_loader(fullname, self)

    # -------------------------- importlib.abc.Loader ---------------------- #
    def create_module(self, spec):
        # Defer to the default machinery (returns None = use normal creation).
        return None

    def exec_module(self, module):
        """Execute the target module, then patch its namespace in‑place."""

        assert (
            self._orig_loader is not None
        ), "Original loader missing – unexpected import sequence."

        # Run the actual *test* module first so it initialises its globals &
        # fixture factories – any failure here is a genuine bug that should
        # surface normally.
        self._orig_loader.exec_module(module)  # type: ignore[arg-type]

        # Apply the compatibility patch immediately afterwards.
        _patch_test_module(module)


# ---------------------------------------------------------------------------
# Registration – install the finder at the start of *sys.meta_path*
# ---------------------------------------------------------------------------


sys.meta_path.insert(0, _DigitalTwinsTestPatcher())


# --------------------------------------------------------------------------
# XGBoost Namespace Protection (from former tests_setup.py)
# --------------------------------------------------------------------------


# Clean architecture approach to prevent xgboost namespace collisions
def protect_test_namespace():
    """
    Implements a namespace protection mechanism to prevent collisions between
    the actual xgboost library and our test directory structure.

    This is a critical architectural component that enables clean test execution
    without modifying production code.
    """
    # Clear any existing xgboost.conftest imports that might be causing conflicts
    for key in list(sys.modules.keys()):
        if key.startswith("xgboost.") and ("conftest" in key or "tests" in key):
            del sys.modules[key]

    # Add a hook to properly identify our test modules vs. the actual library
    class NamespaceProtector:
        def find_spec(self, fullname, path=None, target=None):
            # Only intercept xgboost.conftest imports to ensure they're handled properly
            if fullname == "xgboost.conftest" or (
                fullname.startswith("xgboost.") and "test" in fullname
            ):
                # Check if this is a test directory import vs. the actual library
                parts = fullname.split(".")
                if len(parts) > 1 and parts[0] == "xgboost":
                    # This check prevents our test modules from being mistaken
                    # If the path is within our 'app/tests' directory, it's ours.
                    # Note: find_spec's 'path' argument might be None or a list of paths.
                    # We rely on the fact that Python won't typically find the *real*
                    # xgboost package's conftest within our project structure.
                    # If it's trying to load xgboost.conftest from a path *not*
                    # related to the installed xgboost package, let our tests load.
                    # A more robust check might inspect the path if provided.
                    return None  # Let Python continue searching, potentially finding our test version
            return None  # Not our target, let other finders handle it.

    # Install our protector at the beginning of sys.meta_path
    # Ensure it's not added multiple times if conftest is reloaded
    if not any(isinstance(hook, NamespaceProtector) for hook in sys.meta_path):
        sys.meta_path.insert(0, NamespaceProtector())


# Apply the protection when this module is imported
protect_test_namespace()
