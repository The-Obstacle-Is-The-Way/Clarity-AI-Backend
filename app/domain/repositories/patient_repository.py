"""
Interface for the Patient Repository.
"""
from abc import abstractmethod
from typing import Any
from uuid import UUID

from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
from app.domain.entities.patient import Patient


# Rename class to match import in DI container -> Renaming back to PatientRepository
class PatientRepository(BaseRepositoryInterface[Patient]):  # Renamed from PatientRepositoryInterface
    """Abstract base class defining the patient repository interface."""

    @abstractmethod
    async def get_by_id(self, entity_id: str | UUID) -> Patient | None:
        """Retrieve a patient by their ID.
        
        Args:
            entity_id: Unique identifier for the patient
            
        Returns:
            Patient entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def create(self, entity: Patient) -> Patient:
        """Create a new patient record.
        
        Args:
            entity: Patient entity to create
            
        Returns:
            Created patient entity with populated ID and timestamps
        """
        pass

    @abstractmethod
    async def update(self, entity: Patient) -> Patient:
        """Update an existing patient record.
        
        Args:
            entity: Patient entity with updated data
            
        Returns:
            Updated patient entity
            
        Raises:
            EntityNotFoundError: If the patient doesn't exist
        """
        pass

    @abstractmethod
    async def delete(self, entity_id: str | UUID) -> bool:
        """Delete a patient record by their ID.
        
        Args:
            entity_id: Unique identifier for the patient to delete
            
        Returns:
            True if deletion was successful, False if patient not found
        """
        pass

    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[Patient]:
        """List all patients with pagination.
        
        Args:
            skip: Number of patients to skip for pagination
            limit: Maximum number of patients to return
            
        Returns:
            List of patient entities
        """
        pass

    @abstractmethod
    async def count(self, **filters) -> int:
        """Count the number of patients matching the given filters.
        
        Args:
            **filters: Optional filtering criteria
            
        Returns:
            The count of matching patients
        """
        pass

    @abstractmethod
    async def get_by_email(
        self, 
        email: str,
        context: dict[str, Any] | None = None
    ) -> Patient | None:
        """Find a patient by email address.
        
        Args:
            email: Patient's email address
            context: Optional context for HIPAA audit logging (user_id, action, etc.)
            
        Returns:
            Patient entity if found, None otherwise
        """
        pass

    # Add other specific query methods if needed, e.g.:
    # @abstractmethod
    # async def find_by_email(self, email: str) -> Optional[Patient]:
    #     """Find a patient by email address."""
    #     pass
