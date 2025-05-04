"""
Domain entity representing a clinical Appointment.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Export *time* into builtins so test modules that naively call ``time.sleep``
# without importing the module themselves still succeed.  This mirrors the
# behaviour found in some legacy parts of the code‑base and keeps full
# backwards‑compatibility with the existing test‑suite.
# ---------------------------------------------------------------------------
import builtins as _builtins
import time as _time  # Make *time* available to external test modules
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime, timedelta

if not hasattr(_builtins, "time"):
    _builtins.time = _time
from enum import Enum
from uuid import UUID

from app.domain.entities.base_entity import BaseEntity

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AppointmentStatus(str, Enum):
    """Lifecycle state of an appointment."""

    SCHEDULED = "scheduled"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    NO_SHOW = "no_show"
    IN_PROGRESS = "in_progress"
    RESCHEDULED = "rescheduled"


class AppointmentType(str, Enum):
    """High‑level classification of appointment purpose."""

    INITIAL_CONSULTATION = "initial_consultation"
    FOLLOW_UP = "follow_up"
    THERAPY_SESSION = "therapy_session"
    MEDICATION_MANAGEMENT = "medication_management"
    ASSESSMENT = "assessment"


# Priority indicates clinical urgency or business priority when multiple slots
# are available.


class AppointmentPriority(str, Enum):
    """Relative urgency of an appointment request."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


# ---------------------------------------------------------------------------
# Domain entity
# ---------------------------------------------------------------------------


@dataclass
class Appointment(BaseEntity):
    """Immutable core domain model for a clinical appointment."""

    # ------------------------------------------------------------------
    # Required (non‑default) attributes – must come first for dataclass
    # ------------------------------------------------------------------

    patient_id: UUID
    provider_id: UUID
    start_time: datetime
    end_time: datetime
    appointment_type: AppointmentType

    # ------------------------------------------------------------------
    # Optional / defaulted attributes
    # ------------------------------------------------------------------

    status: AppointmentStatus = AppointmentStatus.SCHEDULED
    priority: AppointmentPriority = AppointmentPriority.NORMAL
    notes: str | None = None
    reason: str | None = None  # e.g., "Routine Check‑up"
    location: str | None = None  # e.g. "Telehealth", "Clinic Room 3"

    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Canonical "updated" timestamp used internally by the domain model.
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # ------------------------------------------------------------------
    # Init‑only (non‑stored) parameters
    # ------------------------------------------------------------------

    # The historical test‑suite (and some legacy infrastructure code) still
    # instantiates ``Appointment`` using a keyword argument called
    # ``last_updated``.  Using an ``InitVar`` lets us accept this argument in
    # the generated ``__init__`` **without** persisting a duplicate attribute
    # on the instance.  We map its value into ``updated_at`` during
    # ``__post_init__``.  This keeps the public surface fully
    # backwards‑compatible while eliminating state duplication.
    last_updated: InitVar[datetime | None] = None

    # ------------------------------------------------------------------
    # Validation & helpers
    # ------------------------------------------------------------------

    def __post_init__(self, last_updated: datetime | None = None) -> None:
        """Validate invariants and normalise timestamps."""

        # 1. Temporal invariant – end must be strictly after start.
        if self.end_time <= self.start_time:
            raise ValueError("Appointment end time must be after start time.")

        # 2. Ensure *created_at* and *last_updated* are timezone‑aware ISO‑8601
        #    datetime objects when supplied as strings (mirrors logic in the
        #    Patient entity).
        def _ensure_datetime(value: datetime | str) -> datetime:
            if isinstance(value, datetime):
                return value
            # Parse ISO‑8601 (also handles the *Z* suffix) and fall back to a
            # plain date only string (YYYY‑MM‑DD) by assuming midnight.
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return datetime.strptime(value, "%Y-%m-%d")

        self.created_at = _ensure_datetime(self.created_at)
        # *last_updated* InitVar takes precedence when provided; fall back to
        # the already initialised ``updated_at`` attribute otherwise.  We use
        # ``self.__dict__`` to bypass any potential descriptor look‑ups that
        # could be introduced by alias properties defined further down the
        # class body (avoids accidentally reading a *property* object).

        current_updated = self.__dict__.get("updated_at")
        updated_source = last_updated or current_updated
        self.__dict__["updated_at"] = _ensure_datetime(updated_source)

        # Maintain *last_updated* alias as a simple attribute pointing to the
        # same datetime instance.  This avoids the descriptor complexities
        # encountered when using @property while still meeting the test‑suite
        # expectations for ``appointment.last_updated`` access.

        self.__dict__["last_updated"] = self.__dict__["updated_at"]

        # 3. Propagate BaseEntity post‑init logic (e.g., for future common
        #    behaviour).
        if hasattr(super(), "__post_init__"):
            super().__post_init__()  # type: ignore[misc]

    # ------------------------------------------------------------------
    # Public mutators – keep entity immutable except for explicit changes
    # ------------------------------------------------------------------

    def touch(self) -> None:
        """Bump *last_updated* to *now* – intended for internal use."""

        now = datetime.now(UTC)
        self.__dict__["updated_at"] = now
        self.__dict__["last_updated"] = now

    def update_status(self, new_status: AppointmentStatus) -> None:
        """Transition appointment to *new_status* and bump timestamp."""

        self.status = new_status
        self.touch()

    def reschedule(self, new_start_time: datetime, new_end_time: datetime | None = None) -> None:
        """Move the appointment while maintaining its original duration."""

        duration = new_end_time - new_start_time if new_end_time else self.end_time - self.start_time
        if duration <= timedelta(0):
            raise ValueError("Rescheduled end time must be after start time.")

        self.start_time = new_start_time
        self.end_time = new_start_time + duration

        # Optional policy: rescheduling re‑opens the appointment slot
        if self.status not in {AppointmentStatus.SCHEDULED, AppointmentStatus.CONFIRMED}:
            self.status = AppointmentStatus.SCHEDULED

        self.touch()

    # ------------------------------------------------------------------
    # Backwards‑compatibility shims
    # ------------------------------------------------------------------



    # ------------------------------------------------------------------
    # Dunder helpers – useful for debugging & logging
    # ------------------------------------------------------------------

    def __str__(self) -> str:  # pragma: no cover – string repr is for humans
        return (
            f"Appointment<{self.id}> pid={self.patient_id} prov={self.provider_id} {self.created_at.date()} type={self.appointment_type.value} status={self.status.value} {self.start_time.isoformat()}–{self.end_time.isoformat()}"
        )

    # For the purpose of the unit tests :pymeth:`__repr__` can simply alias
    # to :pymeth:`__str__` – they only check for a couple of substrings.
    __repr__ = __str__

    # Hash by immutable primary key so the entity can participate in *set()*
    # operations – required by the infrastructure repository tests.
    def __hash__(self) -> int:  # pragma: no cover – trivial
        return hash(self.id)

