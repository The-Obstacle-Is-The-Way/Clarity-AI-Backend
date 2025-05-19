"""
Patient Repository Interface - Core Domain Interface

This module defines the interface for Patient repository implementations,
following clean architecture principles with hexagonal ports and adapters.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from uuid import UUID


class IPatientRepository(ABC):
    """
    Interface for Patient repository implementations.
    Defines the contract for storage and retrieval of Patient data.
    """

    @abstractmethod
    async def create_patient(self, patient_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new patient.

        Args:
            patient_data: Data for the patient

        Returns:
            The created patient with ID
        """
        pass

    @abstractmethod
    async def get_patient(
        self, patient_id: Union[str, UUID]
    ) -> Optional[Dict[str, Any]]:
        """
        Get a patient by ID.

        Args:
            patient_id: Patient ID

        Returns:
            Patient data if found, None otherwise
        """
        pass

    @abstractmethod
    async def update_patient(
        self, patient_id: Union[str, UUID], patient_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Update a patient.

        Args:
            patient_id: Patient ID
            patient_data: Updated data

        Returns:
            Updated patient if found, None otherwise
        """
        pass

    @abstractmethod
    async def delete_patient(self, patient_id: Union[str, UUID]) -> bool:
        """
        Delete a patient.

        Args:
            patient_id: Patient ID

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    async def list_patients(
        self, query: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        List all patients, optionally filtered by query.

        Args:
            query: Optional query parameters

        Returns:
            List of patients
        """
        pass
