"""
Mock Patient Repository - Clean Architecture Implementation

This module provides a mock implementation of the Patient repository interface
for testing purposes, maintaining clean architecture principles.
"""

from typing import Any, cast
from uuid import UUID, uuid4

from app.core.interfaces.repositories.patient_repository_interface import (
    IPatientRepository,
)


class MockPatientRepository(IPatientRepository):
    """
    Mock implementation of the Patient repository interface.
    Used for testing and development without requiring external dependencies.
    """

    def __init__(self):
        """Initialize the mock repository with in-memory storage."""
        self._patients = {}

    async def save(self, patient):
        """
        Save a patient object.

        Args:
            patient: Patient object to save

        Returns:
            The saved patient
        """
        patient_dict = {
            "id": str(patient.id),
            "first_name": patient.first_name,
            "last_name": patient.last_name,
            "date_of_birth": patient.date_of_birth.isoformat() if patient.date_of_birth else None,
            "gender": patient.gender,
            "email": patient.email,
            "phone": patient.phone,
            "diagnoses": patient.diagnoses,
            "medications": patient.medications,
            "allergies": patient.allergies,
            "created_at": "2025-05-14T15:00:00Z",
            "updated_at": "2025-05-14T15:00:00Z",
            "status": "active",
        }

        # Store in memory
        self._patients[str(patient.id)] = patient_dict

        return patient

    async def create_patient(self, patient_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new patient.

        Args:
            patient_data: Data for the patient

        Returns:
            The created patient with ID
        """
        patient_id = str(uuid4())

        # Create the patient with an ID
        patient = {
            "id": patient_id,
            **patient_data,
            "created_at": "2025-05-14T15:00:00Z",
            "updated_at": "2025-05-14T15:00:00Z",
            "status": "active",
        }

        # Store in memory
        self._patients[patient_id] = patient

        return patient

    async def get_patient(self, patient_id: str | UUID) -> dict[str, Any] | None:
        """
        Get a patient by ID.

        Args:
            patient_id: Patient ID

        Returns:
            Patient data if found, None otherwise
        """
        patient_id_str = str(patient_id)
        result = self._patients.get(patient_id_str)
        if result is not None:
            # Ensure we return the correct type by casting the known dict
            return cast(dict[str, Any], result)
        return None

    async def update_patient(
        self, patient_id: str | UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Update a patient.

        Args:
            patient_id: Patient ID
            patient_data: Updated data

        Returns:
            Updated patient if found, None otherwise
        """
        patient_id_str = str(patient_id)

        if patient_id_str not in self._patients:
            return None

        # Update the patient
        patient = self._patients[patient_id_str]
        patient.update(patient_data)
        patient["updated_at"] = "2025-05-14T15:05:00Z"

        return patient

    async def delete_patient(self, patient_id: str | UUID) -> bool:
        """
        Delete a patient.

        Args:
            patient_id: Patient ID

        Returns:
            True if deleted, False if not found
        """
        patient_id_str = str(patient_id)

        if patient_id_str not in self._patients:
            return False

        # Remove from storage
        del self._patients[patient_id_str]

        return True

    async def list_patients(self, query: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """
        List all patients, optionally filtered by query.

        Args:
            query: Optional query parameters

        Returns:
            List of patients
        """
        if query is None:
            return list(self._patients.values())

        filtered_patients = []

        # Filter patients based on query
        for patient in self._patients.values():
            matches = True

            for key, value in query.items():
                if key not in patient or patient[key] != value:
                    matches = False
                    break

            if matches:
                filtered_patients.append(patient)

        return filtered_patients
