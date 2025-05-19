"""
Interface for the Clinical Session Repository.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.domain.entities.clinical_session import ClinicalSession


class IClinicalSessionRepository(ABC):
    """Abstract base class defining the clinical session repository interface."""

    @abstractmethod
    async def get_by_id(self, session_id: UUID) -> ClinicalSession | None:
        """Retrieve a clinical session by its ID."""
        pass

    @abstractmethod
    async def create(self, session: ClinicalSession) -> ClinicalSession:
        """Create a new clinical session record."""
        pass

    @abstractmethod
    async def update(self, session: ClinicalSession) -> ClinicalSession | None:
        """Update an existing clinical session record."""
        pass

    @abstractmethod
    async def delete(self, session_id: UUID) -> bool:
        """Delete a clinical session record by its ID."""
        pass

    @abstractmethod
    async def list_by_patient_id(
        self,
        patient_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[ClinicalSession]:
        """List clinical sessions for a specific patient, optionally filtered by date range."""
        pass

    @abstractmethod
    async def list_by_provider_id(
        self,
        provider_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[ClinicalSession]:
        """List clinical sessions for a specific provider, optionally filtered by date range."""
        pass

    @abstractmethod
    async def list_by_appointment_id(
        self, appointment_id: UUID
    ) -> list[ClinicalSession]:
        """List clinical sessions associated with a specific appointment ID."""
        pass
