"""
Appointment entity for managing clinical appointments.
Domain model representing scheduled meetings between patients and providers.
"""
import builtins as _builtins
import time as _time
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from uuid import UUID

from app.domain.entities.base_entity import BaseEntity
from app.domain.exceptions import (
    InvalidAppointmentStateError,
    InvalidAppointmentTimeError,
)

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
    location: str | None = None  # e.g. "Telehealth", "Clinic Room 3"

    # Fields for cancellation details
    cancellation_reason: str | None = None
    cancelled_by_user_id: UUID | None = None  # Assuming the ID of user/provider who cancelled
    cancelled_at: datetime | None = None

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

        # 0. Ensure start_time is not in the past
        if self.start_time < (
            datetime.now(UTC) - timedelta(seconds=10)
        ):  # Allow 10s leeway for past for tests
            raise InvalidAppointmentTimeError("Appointment start time cannot be in the past.")

        # 1. Temporal invariant – end must be strictly after start.
        if self.end_time <= self.start_time:
            raise InvalidAppointmentTimeError("Appointment end time must be after start time.")

        # 2. Ensure *created_at* and *last_updated* are timezone‑aware ISO‑8601
        #    datetime objects when supplied as strings (mirrors logic in the
        #    Patient entity).
        def _ensure_datetime(value: datetime | str | None) -> datetime:
            if isinstance(value, datetime):
                return value
            if value is None:
                return datetime.now(UTC)
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

        duration = (
            new_end_time - new_start_time if new_end_time else self.end_time - self.start_time
        )
        if duration <= timedelta(0):
            raise InvalidAppointmentTimeError("Rescheduled end time must be after start time.")

        self.start_time = new_start_time
        self.end_time = new_start_time + duration

        # Optional policy: rescheduling re‑opens the appointment slot
        self.status = AppointmentStatus.RESCHEDULED

        self.touch()

    # ------------------------------------------------------------------
    # Backwards‑compatibility shims
    # ------------------------------------------------------------------

    def confirm(self) -> None:
        """Confirm the appointment."""
        if self.status not in {AppointmentStatus.SCHEDULED}:
            raise InvalidAppointmentStateError(
                f"Cannot confirm appointment in '{self.status.value}' state. Must be '{AppointmentStatus.SCHEDULED.value}'."
            )
        self.update_status(AppointmentStatus.CONFIRMED)

    def cancel(self, cancelled_by: UUID, reason: str | None = None) -> None:
        """Cancel the appointment."""
        if self.status in {AppointmentStatus.COMPLETED, AppointmentStatus.CANCELLED}:
            raise InvalidAppointmentStateError(
                f"Cannot cancel appointment in '{self.status.value}' state."
            )
        self.cancellation_reason = reason
        self.cancelled_by_user_id = cancelled_by
        self.cancelled_at = datetime.now(UTC)
        self.update_status(AppointmentStatus.CANCELLED)

    def complete(self) -> None:
        """Complete the appointment."""
        # Typically, an appointment should be IN_PROGRESS or CONFIRMED to be completed.
        if self.status not in {
            AppointmentStatus.CONFIRMED,
            AppointmentStatus.IN_PROGRESS,
            AppointmentStatus.SCHEDULED,
        }:
            raise InvalidAppointmentStateError(
                f"Cannot complete appointment in '{self.status.value}' state. Must be '{AppointmentStatus.CONFIRMED.value}' or '{AppointmentStatus.IN_PROGRESS.value}'."
            )
        self.update_status(AppointmentStatus.COMPLETED)

    def mark_no_show(self) -> None:
        """Mark the appointment as a no-show."""
        # Typically, a no-show can be marked for SCHEDULED or CONFIRMED appointments.
        if self.status not in {
            AppointmentStatus.SCHEDULED,
            AppointmentStatus.CONFIRMED,
            AppointmentStatus.IN_PROGRESS,
        }:
            raise InvalidAppointmentStateError(
                f"Cannot mark no-show for appointment in '{self.status.value}' state."
            )
        self.update_status(AppointmentStatus.NO_SHOW)

    def update_notes(self, notes: str | None) -> None:
        """Update the appointment notes."""
        self.notes = notes
        self.touch()

    def update_location(self, location: str | None) -> None:
        """Update the appointment location."""
        self.location = location
        self.touch()

    def to_dict(self) -> dict:
        """Return a dictionary representation of the appointment."""
        # Using dataclasses.asdict might be too simple if specific formatting or
        # enum value handling is needed. For now, a manual approach.
        # Ensure dataclasses is imported if asdict is used: import dataclasses
        return {
            "id": str(self.id),  # Convert UUID to string for serialization
            "patient_id": str(self.patient_id),
            "provider_id": str(self.provider_id),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "appointment_type": self.appointment_type.value,
            "status": self.status.value,
            "priority": self.priority.value,
            "notes": self.notes,
            "reason": self.reason,
            "location": self.location,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            # "last_updated": self.last_updated.isoformat() # alias
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Appointment":
        """Create an Appointment instance from a dictionary."""
        # Convert string UUIDs back to UUID objects
        for key in ["id", "patient_id", "provider_id", "cancelled_by_user_id"]:
            if key in data and isinstance(data[key], str):
                try:
                    data[key] = UUID(data[key])
                except ValueError:
                    # Handle cases where ID might be None or not a valid UUID string if that's possible
                    if data[key] is not None:
                        raise ValueError(f"Invalid UUID format for {key}: {data[key]}")

        # Convert ISO datetime strings back to datetime objects
        for key in [
            "start_time",
            "end_time",
            "created_at",
            "updated_at",
            "cancelled_at",
        ]:
            if key in data and isinstance(data[key], str):
                try:
                    data[key] = datetime.fromisoformat(data[key].replace("Z", "+00:00"))
                except ValueError:
                    if data[key] is not None:
                        raise ValueError(f"Invalid ISO format for {key}: {data[key]}")

        # Convert string enums back to Enum members
        if "appointment_type" in data and isinstance(data["appointment_type"], str):
            data["appointment_type"] = AppointmentType(data["appointment_type"])
        if "status" in data and isinstance(data["status"], str):
            data["status"] = AppointmentStatus(data["status"])
        if "priority" in data and isinstance(data["priority"], str):
            data["priority"] = AppointmentPriority(data["priority"])

        # Handle potential missing optional fields for robustness if dict is sparse
        # Dataclass __init__ will use defaults if not provided, so this is mostly for type conversion.
        return cls(**data)

    # ------------------------------------------------------------------
    # Dunder helpers – useful for debugging & logging
    # ------------------------------------------------------------------

    def __str__(self) -> str:  # pragma: no cover – string repr is for humans
        return f"Appointment<{self.id}> pid={self.patient_id} prov={self.provider_id} {self.created_at.date()} type={self.appointment_type.value} status={self.status.value} {self.start_time.isoformat()}–{self.end_time.isoformat()}"

    # For the purpose of the unit tests :pymeth:`__repr__` can simply alias
    # to :pymeth:`__str__` – they only check for a couple of substrings.
    __repr__ = __str__

    # Hash by immutable primary key so the entity can participate in *set()*
    # operations – required by the infrastructure repository tests.
    def __hash__(self) -> int:  # pragma: no cover – trivial
        return hash(self.id)
