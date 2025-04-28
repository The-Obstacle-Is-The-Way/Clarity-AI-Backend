# -*- coding: utf-8 -*-
"""Use case for updating an existing patient."""

from app.domain.services.patient_service import PatientService
from app.domain.entities.patient import Patient


class UpdatePatientUseCase:
    """Use case for updating patient information."""

    def __init__(self, patient_service: PatientService):
        self.patient_service = patient_service

    async def execute(self, patient_id: str, updated_data: dict) -> Patient:
        """Execute the use case to update a patient.

        Args:
            patient_id: The ID of the patient to update.
            updated_data: A dict of fields to update.

        Returns:
            The updated Patient entity.
        """
        return await self.patient_service.update(patient_id, updated_data)