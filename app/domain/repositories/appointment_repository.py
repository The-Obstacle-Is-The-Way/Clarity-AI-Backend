"""
Interface for the Appointment Repository.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.domain.entities.appointment import Appointment, AppointmentStatus


class IAppointmentRepository(ABC):
    """Abstract base class defining the appointment repository interface."""

    @abstractmethod
    async def get_by_id(self, appointment_id: UUID) -> Appointment | None:
        """Retrieve an appointment by its ID."""
        pass

    @abstractmethod
    async def create(self, appointment: Appointment) -> Appointment:
        """Create a new appointment."""
        pass

    @abstractmethod
    async def update(self, appointment: Appointment) -> Appointment | None:
        """Update an existing appointment."""
        pass

    @abstractmethod
    async def delete(self, appointment_id: UUID) -> bool:
        """Delete an appointment by its ID."""
        pass

    @abstractmethod
    async def list_by_patient_id(
        self,
        patient_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        status: AppointmentStatus | None = None
    ) -> list[Appointment]:
        """List appointments for a specific patient, optionally filtered by date range and status."""
        pass

    @abstractmethod
    async def list_by_provider_id(
        self,
        provider_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        status: AppointmentStatus | None = None
    ) -> list[Appointment]:
        """List appointments for a specific provider, optionally filtered by date range and status."""
        pass

    @abstractmethod
    async def find_overlapping_appointments(
        self,
        provider_id: UUID,
        start_time: datetime,
        end_time: datetime,
        exclude_appointment_id: UUID | None = None
    ) -> list[Appointment]:
        """Find appointments for a provider that overlap with a given time slot, excluding a specific appointment."""
        pass


# ---------------------------------------------------------------------------
# Backwards‑compatibility alias
# ---------------------------------------------------------------------------

# Earlier revisions of the code‑base – and by extension several test‑suites –
# referred to the repository interface as ``AppointmentRepository`` instead of
# ``IAppointmentRepository`` (which follows the "I‑prefix" naming convention
# for interfaces).  The following alias keeps those references working without
# duplicating code.


AppointmentRepository = IAppointmentRepository

