# app/application/use_cases/patient/create_patient.py
# Placeholder for the create patient use case
# This use case handles the business logic for creating a new patient in the system


from app.domain.entities.patient import Patient
from app.domain.repositories.patient_repository import PatientRepository


class CreatePatientUseCase:
    """Use case for creating a new patient in the system"""

    def __init__(self, patient_repository: PatientRepository):
        """Initialize with required repositories"""
        self.patient_repository = patient_repository

    async def execute(self, patient_data: dict) -> Patient:
        """
        Execute the use case to create a new patient

        Args:
            patient_data: Dictionary containing patient information

        Returns:
            The created Patient entity

        Raises:
            ValueError: If patient data is invalid
        """
        # Validate and build the Patient entity
        try:
            patient = Patient(**patient_data)
        except TypeError as e:
            raise ValueError(f"Invalid patient data: {e}") from e

        # Delegate to repository to persist the new patient
        return await self.patient_repository.create(patient)
