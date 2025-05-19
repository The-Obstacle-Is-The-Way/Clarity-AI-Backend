"""Project‑local *usercustomize* shim loader (relocated).

The CPython interpreter automatically imports a module named
``usercustomize`` immediately *after* :pymod:`sitecustomize`.  By shipping a
wrapper with that name we were able to regain control in environments that
already provide their own global *sitecustomize* (for example the Homebrew
distribution on macOS).

Moving the wrapper under the *backend* package avoids cluttering the project
root.  To activate it in an interactive REPL or external script simply:

    import bootstrap.usercustomize_wrapper  # noqa: F401 – side‑effects
"""

from __future__ import annotations

import importlib as _importlib
import sys as _sys
from pathlib import Path as _Path

# ---------------------------------------------------------------------------
# Ensure *app* directory is import‑searchable (if needed)
# ---------------------------------------------------------------------------

_repo_root = _Path(__file__).resolve().parent.parent
# Remove logic adding 'backend' to sys.path
# _backend_dir = _repo_root / "backend"
# if str(_backend_dir) not in _sys.path:
#     _sys.path.insert(0, str(_backend_dir))

# ---------------------------------------------------------------------------
# Import the real shim implementation and expose it under the canonical names
# ---------------------------------------------------------------------------

_impl = _importlib.import_module("sitecustomize")

_sys.modules.setdefault("sitecustomize", _impl)

globals().update(_impl.__dict__)

# ---------------------------------------------------------------------------
# Sanity check – verify that the in‑memory *boto3* replacement is active.
# ---------------------------------------------------------------------------

import boto3  # noqa: WPS433 – runtime verification

assert getattr(
    boto3, "__shim__", False
), "boto3 shim not active after importing usercustomize_wrapper"
