"""
Interface for the Appointment Repository.
"""
from abc import ABC, abstractmethod
from typing import Optional, List
from uuid import UUID
from datetime import datetime

from app.domain.entities.appointment import Appointment, AppointmentStatus

class IAppointmentRepository(ABC):
    """Abstract base class defining the appointment repository interface."""

    @abstractmethod
    async def get_by_id(self, appointment_id: UUID) -> Optional[Appointment]:
        """Retrieve an appointment by its ID."""
        pass

    @abstractmethod
    async def create(self, appointment: Appointment) -> Appointment:
        """Create a new appointment."""
        pass

    @abstractmethod
    async def update(self, appointment: Appointment) -> Optional[Appointment]:
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
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        status: Optional[AppointmentStatus] = None
    ) -> List[Appointment]:
        """List appointments for a specific patient, optionally filtered by date range and status."""
        pass

    @abstractmethod
    async def list_by_provider_id(
        self,
        provider_id: UUID,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        status: Optional[AppointmentStatus] = None
    ) -> List[Appointment]:
        """List appointments for a specific provider, optionally filtered by date range and status."""
        pass

    @abstractmethod
    async def find_overlapping_appointments(
        self,
        provider_id: UUID,
        start_time: datetime,
        end_time: datetime,
        exclude_appointment_id: Optional[UUID] = None
    ) -> List[Appointment]:
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


AppointmentRepository = IAppointmentRepository  # noqa: N816 (keep historical camel‑case)

