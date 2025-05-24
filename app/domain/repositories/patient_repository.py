"""
Interface for the Patient Repository.
"""
from abc import ABC, abstractmethod
from uuid import UUID
from typing import Optional, Dict, Any

from app.domain.entities.patient import Patient


# Rename class to match import in DI container -> Renaming back to PatientRepository
class PatientRepository(ABC):  # Renamed from PatientRepositoryInterface
    """Abstract base class defining the patient repository interface."""

    @abstractmethod
    async def get_by_id(
        self, 
        patient_id: UUID, 
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Patient]:
        """Retrieve a patient by their ID.
        
        Args:
            patient_id: Unique identifier for the patient
            context: Optional context for HIPAA audit logging (user_id, action, etc.)
            
        Returns:
            Patient entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def create(
        self, 
        patient: Patient, 
        context: Optional[Dict[str, Any]] = None
    ) -> Patient:
        """Create a new patient record.
        
        Args:
            patient: Patient entity to create
            context: Optional context for HIPAA audit logging (user_id, action, etc.)
            
        Returns:
            Created patient entity with populated ID and timestamps
        """
        pass

    @abstractmethod
    async def update(
        self, 
        patient: Patient, 
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Patient]:
        """Update an existing patient record.
        
        Args:
            patient: Patient entity with updated data
            context: Optional context for HIPAA audit logging (user_id, action, etc.)
            
        Returns:
            Updated patient entity if successful, None if patient not found
        """
        pass

    @abstractmethod
    async def delete(
        self, 
        patient_id: UUID, 
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Delete a patient record by their ID.
        
        Args:
            patient_id: Unique identifier for the patient to delete
            context: Optional context for HIPAA audit logging (user_id, action, etc.)
            
        Returns:
            True if deletion was successful, False if patient not found
        """
        pass

    @abstractmethod
    async def list_all(
        self, 
        limit: int = 100, 
        offset: int = 0,
        context: Optional[Dict[str, Any]] = None
    ) -> list[Patient]:
        """List all patients with pagination.
        
        Args:
            limit: Maximum number of patients to return
            offset: Number of patients to skip for pagination
            context: Optional context for HIPAA audit logging (user_id, action, etc.)
            
        Returns:
            List of patient entities
        """
        pass

    @abstractmethod
    async def get_by_email(
        self, 
        email: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Patient]:
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
