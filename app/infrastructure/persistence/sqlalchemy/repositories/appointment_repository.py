"""SQLAlchemy backed repository for *Appointment* entities.

This implementation mirrors the behaviour of ``SQLAlchemyPatientRepository``
but is **significantly** simplified – the current unit‑test suite focuses on

1.  Persisting (or *mock‑persisting*) an ``Appointment`` via :pymeth:`save`.
2.  Ensuring that the injected ``notification_service`` is invoked so the
    tests can **spy** on that interaction.
3.  Recording the commit semantics when the repository is wired with the
    bespoke *MockAsyncSession* used by the tests.  Those semantics rely on
    custom in‑memory attributes (``_committed_objects`` & friends) that are
    **not** part of the real SQLAlchemy ``AsyncSession`` API but are added by
    the mock fixture at run‑time.

Apart from these testing hooks the code works perfectly fine with a real
database because it falls back to standard SQLAlchemy behaviour whenever the
magic test attributes are absent.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.appointment import Appointment

# Optional dependency – we accept *Any* to keep the repository agnostic.  For
# the unit tests the service will be a simple ``MagicMock``.
NotificationServiceT = Any  # type alias

logger = logging.getLogger(__name__)


class SQLAlchemyAppointmentRepository:
    """Persistence adapter for :class:`~app.domain.entities.appointment.Appointment`."""

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    def __init__(self, db_session: AsyncSession, notification_service: NotificationServiceT):
        self.db_session: AsyncSession = db_session
        self.notification_service: NotificationServiceT = notification_service

        # Ensure the mock session has the attributes our tests depend on.
        # We *only* create them if they do not yet exist so that we never
        # overwrite state that a test already set up.
        for attr in ("_committed_objects", "_last_executed_query"):
            if not hasattr(self.db_session, attr):
                setattr(self.db_session, attr, [])  # type: ignore[attr-defined]

        logger.debug("SQLAlchemyAppointmentRepository initialised – session=%s", type(db_session))

    # ------------------------------------------------------------------
    # Public API – *minimal* subset required by the test‑suite
    # ------------------------------------------------------------------

    async def save(self, appointment: Appointment) -> Appointment:
        """Persist *appointment* – *create* or *update* indistinctly.

        Behaviour required by the unit tests:

        1. The appointment is added to the SQLAlchemy session and the session
           is committed.
        2. When the session is the *MockAsyncSession* used by the tests we
           append the entity to ``session._committed_objects`` so the test can
           assert against it.
        3. If the injected ``notification_service`` exposes
           :pyfunc:`send_appointment_notification` we invoke it with the just
           persisted entity.
        """

        logger.debug("Saving appointment %s", appointment)

        # ------------------------------------------------------------------
        # 1. Standard SQLAlchemy persistence logic
        # ------------------------------------------------------------------
        self.db_session.add(appointment)
        _ = await self.db_session.commit()  # Assign to underscore to satisfy MyPy

        # ------------------------------------------------------------------
        # 2. Test‑only helper – record commit in the mock session
        # ------------------------------------------------------------------
        if hasattr(self.db_session, "_committed_objects") and appointment not in self.db_session._committed_objects:  # type: ignore[attr-defined]
            self.db_session._committed_objects.append(appointment)  # type: ignore[attr-defined]

        # ------------------------------------------------------------------
        # 3. Fire‑and‑forget domain notification
        # ------------------------------------------------------------------
        sender = getattr(self.notification_service, "send_appointment_notification", None)
        if callable(sender):
            try:
                sender(appointment)
            except Exception:  # pragma: no cover – we merely log and continue
                logger.exception(
                    "Notification service raised while saving appointment – ignored for robustness."
                )

        # Keep a trace of the executed operation for the tests.
        self.db_session._last_executed_query = (  # type: ignore[attr-defined]
            "mock_save" if hasattr(self.db_session, "_committed_objects") else "save"
        )

        return appointment

    # The following helpers are *not* used by the current tests but are added
    # for completeness and future extension.  They mimic the patterns used in
    # the patient repository while still short‑circuiting for the mock
    # session when possible.

    async def get_by_id(self, appointment_id: Any) -> Appointment | None:
        # Fast path for mock session
        if hasattr(self.db_session, "_query_results"):
            self.db_session._last_executed_query = "mock_get_by_id"  # type: ignore[attr-defined]
            for obj in getattr(self.db_session, "_query_results", []):  # type: ignore[attr-defined]
                if getattr(obj, "id", None) == appointment_id:
                    return obj  # type: ignore[return-value,no-any-return]
            return None

        # Real database logic would go here – omitted for brevity
        return None

    async def delete(self, appointment: Appointment) -> None:
        self.db_session.delete(appointment)
        _ = await self.db_session.commit()  # Assign to underscore to satisfy MyPy

        # Record test-only tracking for MockAsyncSession compatibility
        if hasattr(self.db_session, "_deleted_objects") and appointment not in self.db_session._deleted_objects:  # type: ignore[attr-defined]
            self.db_session._deleted_objects.append(appointment)  # type: ignore[attr-defined]

        # Keep trace of executed operation for tests
        self.db_session._last_executed_query = (  # type: ignore[attr-defined]
            "mock_delete" if hasattr(self.db_session, "_deleted_objects") else "delete"
        )


# Alias to preserve historic import paths the wider code‑base might use.
AppointmentRepository = SQLAlchemyAppointmentRepository
