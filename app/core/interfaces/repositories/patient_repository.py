# -*- coding: utf-8 -*-
"""
Patient Repository Interface.

This module defines the abstract interface for patient data persistence,
following the Repository Pattern and Dependency Inversion Principle.
Implementations of this interface will handle the specifics of data storage
(e.g., database, file system) while the core application logic depends only
on this abstraction. This ensures decoupling and testability.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from app.core.domain.entities.patient import Patient


class IPatientRepository(ABC):
    """Abstract interface for a patient repository."""

    @abstractmethod
    async def add(self, patient: Patient) -> Patient:
        """
        Adds a new patient to the repository.

        Args:
            patient: The Patient entity to add.

        Returns:
            The added Patient entity, possibly with generated fields like ID.

        Raises:
            RepositoryError: If the patient could not be added (e.g., duplicate).
        """
        pass

    @abstractmethod
    async def get_by_id(self, patient_id: str) -> Optional[Patient]:
        """
        Retrieves a patient by their unique identifier.

        Args:
            patient_id: The unique ID of the patient.

        Returns:
            The Patient entity if found, otherwise None.

        Raises:
            RepositoryError: If there was an error retrieving the patient.
        """
        pass

    @abstractmethod
    async def get_all(self, limit: int = 100, offset: int = 0) -> List[Patient]:
        """
        Retrieves a list of all patients, with pagination.

        Args:
            limit: Maximum number of patients to retrieve.
            offset: Number of patients to skip for pagination.

        Returns:
            A list of Patient entities.

        Raises:
            RepositoryError: If there was an error retrieving the patients.
        """
        pass

    @abstractmethod
    async def update(self, patient: Patient) -> Patient:
        """
        Updates an existing patient in the repository.

        Args:
            patient: The Patient entity with updated information. The ID must match
                     an existing patient.

        Returns:
            The updated Patient entity.

        Raises:
            RepositoryError: If the patient could not be updated (e.g., not found).
        """
        pass

    @abstractmethod
    async def delete(self, patient_id: str) -> bool:
        """
        Deletes a patient from the repository.

        Args:
            patient_id: The unique ID of the patient to delete.

        Returns:
            True if the patient was successfully deleted, False otherwise.

        Raises:
            RepositoryError: If there was an error deleting the patient.
        """
        pass

    @abstractmethod
    async def find_by_criteria(self, criteria: Dict[str, Any]) -> List[Patient]:
        """
        Finds patients based on specific criteria.

        Args:
            criteria: A dictionary of criteria to filter patients (e.g., {"last_name": "Doe"}).

        Returns:
            A list of Patient entities matching the criteria.

        Raises:
            RepositoryError: If there was an error searching for patients.
        """
        pass 