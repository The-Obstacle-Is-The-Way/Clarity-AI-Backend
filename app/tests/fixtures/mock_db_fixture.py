"""mock_db_fixture.py

Light‑weight mock of SQLAlchemy ``AsyncSession`` for unit tests.

This re‑implementation avoids inheriting from ``unittest.mock.MagicMock``
because *MagicMock* eagerly converts **every** attribute access into a
mock object, which breaks business logic that relies on normal Python
attributes (e.g. appending to ``_pending_objects`` lists).  Instead we
provide a small, purpose‑built class that implements only the subset of
behaviour required by our test‑suite:

• ``add`` / ``delete`` – simple CRUD staging.
• ``commit`` / ``rollback`` / ``flush`` / ``close`` – async
  no‑ops that mutate internal state so tests can assert on them.
• ``refresh`` – optional callback so tests can mutate an object upon
  refresh.
• rudimentary ``execute`` + ``scalars`` helpers so select/insert/update
  statements in tests get predictable results.
• minimal ``query`` API supporting the chained pattern
  ``session.query(Model).filter_by(...).first()`` needed by a handful of
  integration tests.

The goal is to stay *extremely* small – just enough to satisfy tests –
while keeping deterministic behaviour and zero external dependencies.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any


class _ScalarResult:
    """Mimics SQLAlchemy ``ScalarResult`` for simple unit tests."""

    def __init__(self, items: Sequence[Any]):
        self._items: list[Any] = list(items)

    # ---------------------------------------------------------------------
    # Public helpers used in the current test‑suite
    # ---------------------------------------------------------------------
    def first(self) -> Any | None:
        return self._items[0] if self._items else None

    def all(self) -> list[Any]:
        return list(self._items)


class _ExecutionResult:
    """Return type for our ``execute`` helper."""

    def __init__(self, items: Sequence[Any]):
        self._items = list(items)

    def scalars(self) -> _ScalarResult:
        return _ScalarResult(self._items)


class _QueryBuilder:
    """Ultra‑simple emulation of ``session.query`` chain."""

    def __init__(self, data: list[Any]):
        # We *copy* so that subsequent filters don't mutate the original.
        self._data: list[Any] = list(data)

    # ------------------------------------------------------------------
    # Chained helpers – only ``filter_by``/``first``/``all`` are needed
    # ------------------------------------------------------------------
    def filter_by(self, **filters: Any) -> _QueryBuilder:
        def _matches(obj: Any) -> bool:
            return all(
                getattr(obj, key, None) == value for key, value in filters.items()
            )

        self._data = [obj for obj in self._data if _matches(obj)]
        return self

    def first(self) -> Any | None:
        return self._data[0] if self._data else None

    def all(self) -> list[Any]:
        return list(self._data)


class MockAsyncSession:  # pylint: disable=too-many-instance-attributes
    """A **very** small subset of SQLAlchemy's *AsyncSession* API."""

    # ------------------------------------------------------------------
    # Life‑cycle helpers (with async context‑manager support)
    # ------------------------------------------------------------------
    def __init__(self) -> None:
        # session state flags ------------------------------------------------
        self.committed: bool = False
        self.rolled_back: bool = False
        self.closed: bool = False
        self.flushed: bool = False

        # simple object registries -----------------------------------------
        self._pending_objects: list[Any] = []
        self._committed_objects: list[Any] = []
        self._deleted_objects: list[Any] = []
        self._entity_registry: dict[Any, Any] = {}

        # misc helpers for assertions --------------------------------------
        self.added_objects: list[Any] = []
        self.deleted_objects: list[Any] = []
        self.refreshed_objects: list[Any] = []
        self.executed_queries: list[str] = []
        self.query_results: dict[str, Any | list[Any]] = {}

        # optional callback invoked during ``refresh`` ----------------------
        self._refresh_callback: callable | None = None

    # ------------------------------------------------------------------
    # Async context‑manager so tests can `async with MockAsyncSession()`
    # ------------------------------------------------------------------
    async def __aenter__(self) -> MockAsyncSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        # On error we *still* close to keep semantics predictable.
        await self.close()

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------
    def add(self, obj: Any) -> None:
        self.added_objects.append(obj)
        self._pending_objects.append(obj)
        if hasattr(obj, "id"):
            # Use the *raw* value – don't rely on UUID hashing specifics
            self._entity_registry[obj.id] = obj

    def delete(self, obj: Any) -> None:
        self.deleted_objects.append(obj)
        self._deleted_objects.append(obj)
        # Remove from committed registry if applicable
        if hasattr(obj, "id") and obj.id in self._entity_registry:
            self._entity_registry.pop(obj.id, None)

    # ------------------------------------------------------------------
    # Transaction helpers (async to mirror SQLAlchemy's API)
    # ------------------------------------------------------------------
    async def commit(self) -> None:
        # Move pending → committed ----------------------------------------
        self._committed_objects.extend(self._pending_objects)
        self._pending_objects.clear()

        # Apply deletions --------------------------------------------------
        for obj in list(self._deleted_objects):
            if obj in self._committed_objects:
                self._committed_objects.remove(obj)
        self._deleted_objects.clear()

        self.committed = True

    async def rollback(self) -> None:
        # Simply drop staged changes – don't touch committed objects.
        self._pending_objects.clear()
        self._deleted_objects.clear()
        self.rolled_back = True

    async def flush(self) -> None:
        # Nothing fancy for a mock – just flip the flag.
        self.flushed = True

    async def close(self) -> None:
        self.closed = True

    # ------------------------------------------------------------------
    # Refresh helper (async)
    # ------------------------------------------------------------------
    async def refresh(self, obj: Any) -> None:
        self.refreshed_objects.append(obj)
        if callable(self._refresh_callback):
            self._refresh_callback(obj)

    def set_refresh_callback(self, callback):
        self._refresh_callback = callback

    # ------------------------------------------------------------------
    # Minimal SELECT/INSERT/UPDATE/DELETE emulation via ``execute``
    # ------------------------------------------------------------------
    async def execute(self, query: Any, *args, **kwargs):
        query_str = str(query)
        self.executed_queries.append(query_str)

        lowered = query_str.lower().strip()
        # SELECT ---------------------------------------------------------
        if lowered.startswith("select"):
            items = self.query_results.get(query_str) or self.query_results.get(
                "unknown_query", []
            )
            return _ExecutionResult(items if isinstance(items, list) else [items])

        # INSERT / UPDATE / DELETE --------------------------------------
        if any(lowered.startswith(prefix) for prefix in ("insert", "update", "delete")):
            return SimpleNamespace(rowcount=1)

        # Fallback – return opaque object
        return SimpleNamespace()

    # Helper used directly by a couple of tests ---------------------------
    async def scalars(self, result: Any, *args, **kwargs):
        # ``result`` could be an *ExecutionResult* or any arbitrary object.
        # Our tests only care that ``scalars().first()`` & ``scalars().all()``
        # work, so we wrap *result* in our helper if needed.
        if isinstance(result, _ExecutionResult):
            return result.scalars()
        return _ScalarResult([result])

    # ------------------------------------------------------------------
    # Very small subset of *synchronous* query API -----------------------
    # ------------------------------------------------------------------
    def query(self, model_class):
        # Pull committed objects that are exactly of type ``model_class``
        items = [obj for obj in self._committed_objects if isinstance(obj, model_class)]
        return _QueryBuilder(items)

    # ------------------------------------------------------------------
    # Convenience helpers for tests to pre‑seed results ------------------
    # ------------------------------------------------------------------
    def set_result(self, results: Any | list[Any]):
        """Configure default *SELECT* results when query string unknown."""
        self.query_results["unknown_query"] = results

    def configure_mock_results(self, query: str, results: Any | list[Any]):
        """Bind *results* to a specific ``query`` string (exact match)."""
        self.query_results[query] = results


# ---------------------------------------------------------------------------
# pytest helpers – allow ``mock_db`` fixture to be imported explicitly in
# standalone tests without duplicating logic elsewhere.
# ---------------------------------------------------------------------------


import pytest


@pytest.fixture
def mock_db():
    """Yield a new *MockAsyncSession* per‑test."""

    session = MockAsyncSession()
    yield session
    # explicit clean‑up not strictly required, but mirrors SQLAlchemy tests
    # and prevents accidental state‑leakage between tests running in the same
    # process when `pytest-xdist` isn't used.
    if not session.closed:
        # ``close`` is async – schedule & run quickly.
        asyncio.get_event_loop().run_until_complete(session.close())
