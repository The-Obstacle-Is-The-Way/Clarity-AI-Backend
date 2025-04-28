"""
Interface for the Patient Repository.
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from uuid import UUID

from app.domain.entities.patient import Patient

# Rename class to match import in DI container -> Renaming back to PatientRepository
class PatientRepository(ABC): # Renamed from PatientRepositoryInterface
    """Abstract base class defining the patient repository interface."""

    @abstractmethod
    async def get_by_id(self, patient_id: UUID) -> Optional[Patient]:
        """Retrieve a patient by their ID."""
        pass

    @abstractmethod
    async def create(self, patient: Patient) -> Patient:
        """Create a new patient record."""
        pass

    @abstractmethod
    async def update(self, patient: Patient) -> Optional[Patient]:
        """Update an existing patient record."""
        pass

    @abstractmethod
    async def delete(self, patient_id: UUID) -> bool:
        """Delete a patient record by their ID."""
        pass

    @abstractmethod
    async def list_all(self, limit: int = 100, offset: int = 0) -> List[Patient]:
        """List all patients with pagination."""
        pass

    # Add other specific query methods if needed, e.g.:
    # @abstractmethod
    # async def find_by_email(self, email: str) -> Optional[Patient]:
    #     """Find a patient by email address."""
    #     pass

