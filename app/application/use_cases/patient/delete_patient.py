# -*- coding: utf-8 -*-
"""Use case for deleting a patient."""

from app.domain.services.patient_service import PatientService


class DeletePatientUseCase:
    """Use case for deleting a patient by ID."""

    def __init__(self, patient_service: PatientService):
        self.patient_service = patient_service

    async def execute(self, patient_id: str) -> bool:
        """Execute the use case to delete a patient.

        Args:
            patient_id: The ID of the patient to delete.

        Returns:
            True if deletion was successful.
        """
        return await self.patient_service.delete(patient_id)