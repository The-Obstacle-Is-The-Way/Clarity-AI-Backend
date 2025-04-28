"""
Interface for the Clinical Session Repository.
"""
from abc import ABC, abstractmethod
from typing import Optional, List
from uuid import UUID
from datetime import datetime

from app.domain.entities.clinical_session import ClinicalSession

class IClinicalSessionRepository(ABC):
    """Abstract base class defining the clinical session repository interface."""

    @abstractmethod
    async def get_by_id(self, session_id: UUID) -> Optional[ClinicalSession]:
        """Retrieve a clinical session by its ID."""
        pass

    @abstractmethod
    async def create(self, session: ClinicalSession) -> ClinicalSession:
        """Create a new clinical session record."""
        pass

    @abstractmethod
    async def update(self, session: ClinicalSession) -> Optional[ClinicalSession]:
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
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[ClinicalSession]:
        """List clinical sessions for a specific patient, optionally filtered by date range."""
        pass

    @abstractmethod
    async def list_by_provider_id(
        self,
        provider_id: UUID,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[ClinicalSession]:
        """List clinical sessions for a specific provider, optionally filtered by date range."""
        pass

    @abstractmethod
    async def list_by_appointment_id(self, appointment_id: UUID) -> List[ClinicalSession]:
        """List clinical sessions associated with a specific appointment ID."""
        pass

