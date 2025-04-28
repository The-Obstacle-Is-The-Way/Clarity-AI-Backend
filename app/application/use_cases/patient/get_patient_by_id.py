# -*- coding: utf-8 -*-
"""Use case for retrieving a patient by ID."""

from app.domain.services.patient_service import PatientService
from app.domain.entities.patient import Patient
from app.domain.exceptions.patient_exceptions import PatientNotFoundError


class GetPatientByIdUseCase:
    """Use case for getting a patient by their ID."""

    def __init__(self, patient_service: PatientService):
        self.patient_service = patient_service

    async def execute(self, patient_id: str) -> Patient:
        """Execute the use case to retrieve a patient by ID.

        Args:
            patient_id: The ID of the patient to retrieve.

        Returns:
            The Patient entity.

        Raises:
            PatientNotFoundError: If no patient is found with the given ID.
        """
        return await self.patient_service.get_by_id(patient_id)