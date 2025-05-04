"""
Patient service module for the NOVAMIND backend.

This module contains the PatientService, which encapsulates complex business logic
related to patient management in the concierge psychiatry practice.
"""

from datetime import date, datetime, timedelta
from uuid import UUID

from app.domain.entities.patient import Patient
from app.domain.exceptions import (
    ValidationError,
)
from app.domain.exceptions.patient_exceptions import PatientNotFoundError
from app.domain.repositories.appointment_repository import IAppointmentRepository
from app.domain.repositories.clinical_note_repository import ClinicalNoteRepository
from app.domain.repositories.patient_repository import PatientRepository
from app.domain.repositories.provider_repository import ProviderRepository
from app.domain.utils.datetime_utils import UTC


class PatientService:
    """
    Service for managing patients in the concierge psychiatry practice.

    This service encapsulates complex business logic related to patient
    management, care coordination, and HIPAA-compliant data handling.
    """

    def __init__(
        self,
        patient_repository: PatientRepository,
        provider_repository: ProviderRepository,
        appointment_repository: IAppointmentRepository,
        clinical_note_repository: ClinicalNoteRepository,
    ):
        """
        Initialize the patient service

        Args:
            patient_repository: Repository for patient data access
            provider_repository: Repository for provider data access
            appointment_repository: Repository for appointment data access
            clinical_note_repository: Repository for clinical note data access
        """
        self.patient_repository = patient_repository
        self.provider_repository = provider_repository
        self.appointment_repository = appointment_repository
        self._note_repo = clinical_note_repository

    async def get_by_id(self, patient_id: str) -> Patient:
        """Retrieve a patient by ID, raising if not found."""
        patient = await self.patient_repository.get_by_id(patient_id)
        if not patient:
            raise PatientNotFoundError(patient_id)
        return patient

    async def create(self, patient_data: dict) -> Patient:
        """Create a new patient using provided data dict."""
        return await self.patient_repository.create(patient_data)

    async def update(self, patient_id: str, updated_data: dict) -> Patient:
        """Update an existing patient by ID with provided fields."""
        await self.get_by_id(patient_id)
        return await self.patient_repository.update(updated_data)

    async def delete(self, patient_id: str) -> bool:
        """Delete a patient by ID, raising if not found."""
        await self.get_by_id(patient_id)
        return await self.patient_repository.delete(patient_id)

    async def register_patient(
        self,
        first_name: str,
        last_name: str,
        date_of_birth: date,
        contact_info: dict,
        insurance_info: dict | None = None,
        emergency_contact: dict | None = None,
        medical_history: dict | None = None,
        preferred_provider_id: UUID | None = None,
    ) -> Patient:
        """
        Register a new patient

        Args:
            first_name: Patient's first name
            last_name: Patient's last name
            date_of_birth: Patient's date of birth
            contact_info: Patient's contact information
            insurance_info: Optional insurance information
            emergency_contact: Optional emergency contact information
            medical_history: Optional medical history
            preferred_provider_id: Optional UUID of preferred provider

        Returns:
            The created patient entity

        Raises:
            ValidationError: If the patient data is invalid
        """
        # Validate date of birth (patient must be at least 18 years old for adult psychiatry)
        today = date.today()
        age = (
            today.year
            - date_of_birth.year
            - ((today.month, today.day) < (date_of_birth.month, date_of_birth.day))
        )
        if age < 18:
            raise ValidationError(
                "Patient must be at least 18 years old for adult psychiatry services"
            )

        # Validate preferred provider if specified
        if preferred_provider_id:
            provider = await self.provider_repository.get_by_id(preferred_provider_id)
            if not provider:
                raise ValidationError(
                    f"Provider with ID {preferred_provider_id} does not exist"
                )

            # Check if provider is accepting patients
            if not provider.accepts_new_patients or not provider.is_active:
                raise ValidationError(
                    f"Provider {provider.full_name} is not accepting new patients"
                )

        # Create patient entity
        patient = Patient(
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            contact_info=contact_info,
        )

        # Add optional information
        if insurance_info:
            patient.insurance_info = insurance_info

        if emergency_contact:
            patient.emergency_contact = emergency_contact

        if medical_history:
            patient.medical_history = medical_history

        if preferred_provider_id:
            patient.preferred_provider_id = preferred_provider_id

        # Save to repository
        return await self.patient_repository.create(patient)

    async def update_patient_info(
        self, patient_id: UUID, updated_fields: dict
    ) -> Patient:
        """
        Update patient information

        Args:
            patient_id: UUID of the patient
            updated_fields: Dictionary of fields to update

        Returns:
            The updated patient entity

        Raises:
            ValidationError: If the patient data is invalid
        """
        # Retrieve the patient
        patient = await self.patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValidationError(f"Patient with ID {patient_id} does not exist")

        # Update fields
        for field, value in updated_fields.items():
            if hasattr(patient, field):
                setattr(patient, field, value)
            else:
                raise ValidationError(f"Invalid field: {field}")

        # Save to repository
        return await self.patient_repository.update(patient)

    async def get_patient_care_summary(self, patient_id: UUID) -> dict:
        """
        Get a comprehensive care summary for a patient

        Args:
            patient_id: UUID of the patient

        Returns:
            Dictionary containing patient care summary

        Raises:
            ValidationError: If the patient doesn't exist
        """
        # Retrieve the patient
        patient = await self.patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValidationError(f"Patient with ID {patient_id} does not exist")

        # Get recent appointments
        recent_appointments = await self.appointment_repository.list_by_patient(
            patient_id=patient_id, limit=5, offset=0
        )

        # Get upcoming appointments
        upcoming_appointments = await self.appointment_repository.list_upcoming_by_patient(
            patient_id=patient_id, limit=5
        )

        # Get recent clinical notes
        recent_notes = await self._note_repo.list_by_patient(
            patient_id=patient_id, limit=5, offset=0
        )

        # Get preferred provider if set
        preferred_provider = None
        if patient.preferred_provider_id:
            preferred_provider = await self.provider_repository.get_by_id(
                patient.preferred_provider_id
            )

        # Compile care summary
        care_summary = {
            "patient": {
                "id": str(patient.id),
                "name": f"{patient.first_name} {patient.last_name}",
                "date_of_birth": patient.date_of_birth.isoformat(),
                "age": self._calculate_age(patient.date_of_birth),
            },
            "preferred_provider": (
                {
                    "id": str(preferred_provider.id),
                    "name": preferred_provider.full_name,
                    "role": preferred_provider.role.name,
                }
                if preferred_provider
                else None
            ),
            "recent_appointments": [
                {
                    "id": str(appt.id),
                    "date": appt.appointment_date.isoformat(),
                    "type": (
                        appt.appointment_type.name
                        if hasattr(appt, "appointment_type")
                        else None
                    ),
                    "status": appt.status.name if hasattr(appt, "status") else None,
                }
                for appt in recent_appointments
            ],
            "upcoming_appointments": [
                {
                    "id": str(appt.id),
                    "date": appt.appointment_date.isoformat(),
                    "type": (
                        appt.appointment_type.name
                        if hasattr(appt, "appointment_type")
                        else None
                    ),
                    "status": appt.status.name if hasattr(appt, "status") else None,
                }
                for appt in upcoming_appointments
            ],
            "recent_notes": [
                {
                    "id": str(note.id),
                    "date": note.created_at.isoformat(),
                    "type": note.note_type.name if hasattr(note, "note_type") else None,
                    "provider_id": str(note.provider_id),
                }
                for note in recent_notes
            ],
        }

        return care_summary

    async def assign_preferred_provider(
        self, patient_id: UUID, provider_id: UUID
    ) -> Patient:
        """
        Assign a preferred provider to a patient

        Args:
            patient_id: UUID of the patient
            provider_id: UUID of the provider

        Returns:
            The updated patient entity

        Raises:
            ValidationError: If the patient or provider doesn't exist
        """
        # Retrieve the patient
        patient = await self.patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValidationError(f"Patient with ID {patient_id} does not exist")

        # Verify provider exists
        provider = await self.provider_repository.get_by_id(provider_id)
        if not provider:
            raise ValidationError(f"Provider with ID {provider_id} does not exist")

        # Update preferred provider
        patient.preferred_provider_id = provider_id

        # Save to repository
        return await self.patient_repository.update(patient)

    async def get_patient_medication_history(self, patient_id: UUID) -> list[dict]:
        """
        Get medication history for a patient

        Args:
            patient_id: UUID of the patient

        Returns:
            List of medication entries

        Raises:
            ValidationError: If the patient doesn't exist
        """
        # Retrieve the patient
        patient = await self.patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValidationError(f"Patient with ID {patient_id} does not exist")

        # Get all notes for the patient
        notes = await self._note_repo.list_by_patient(patient_id, limit=1000, offset=0)

        # Extract medication entries from notes
        medication_history = []
        for note in notes:
            if hasattr(note, "medications") and note.medications:
                for med in note.medications:
                    medication_entry = {
                        "name": med.name,
                        "dosage": med.dosage,
                        "frequency": med.frequency,
                        "start_date": med.start_date.isoformat(),
                        "end_date": med.end_date.isoformat() if med.end_date else None,
                        "prescriber_id": str(med.prescriber_id),
                        "reason": med.reason,
                        "notes": med.notes,
                        "note_id": str(note.id),
                        "note_date": note.created_at.isoformat(),
                    }
                    medication_history.append(medication_entry)

        # Sort by start date (newest first)
        medication_history.sort(key=lambda x: x["start_date"], reverse=True)

        return medication_history

    async def get_patient_diagnosis_history(self, patient_id: UUID) -> list[dict]:
        """
        Get diagnosis history for a patient

        Args:
            patient_id: UUID of the patient

        Returns:
            List of diagnosis entries

        Raises:
            ValidationError: If the patient doesn't exist
        """
        # Retrieve the patient
        patient = await self.patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValidationError(f"Patient with ID {patient_id} does not exist")

        # Get all notes for the patient
        notes = await self._note_repo.list_by_patient(patient_id, limit=1000, offset=0)

        # Extract diagnosis entries from notes
        diagnosis_history = []
        for note in notes:
            if hasattr(note, "diagnoses") and note.diagnoses:
                for diag in note.diagnoses:
                    diagnosis_entry = {
                        "code": diag.code,
                        "description": diag.description,
                        "primary": diag.primary,
                        "date_diagnosed": diag.date_diagnosed.isoformat(),
                        "notes": diag.notes,
                        "note_id": str(note.id),
                        "note_date": note.created_at.isoformat(),
                    }
                    diagnosis_history.append(diagnosis_entry)

        # Sort by date diagnosed (newest first)
        diagnosis_history.sort(key=lambda x: x["date_diagnosed"], reverse=True)

        return diagnosis_history

    async def search_patients(
        self, query: str, limit: int = 20, offset: int = 0
    ) -> list[Patient]:
        """
        Search for patients by name or other fields

        Args:
            query: The search query
            limit: Maximum number of patients to return
            offset: Number of patients to skip

        Returns:
            List of matching patient entities
        """
        return await self.patient_repository.search(query, limit, offset)

    async def get_patients_with_upcoming_appointments(
        self, days_ahead: int = 7
    ) -> list[dict]:
        """
        Get patients with upcoming appointments within a specified number of days

        Args:
            days_ahead: Number of days to look ahead

        Returns:
            List of patients with their upcoming appointments
        """
        # Calculate date range
        start_date = datetime.now(UTC)
        end_date = start_date + timedelta(days=days_ahead)

        # Get appointments in date range
        appointments = await self.appointment_repository.list_by_date_range(
            start_date, end_date
        )

        # Group appointments by patient
        patient_appointments = {}
        for appt in appointments:
            patient_id = str(appt.patient_id)
            if patient_id not in patient_appointments:
                patient_appointments[patient_id] = []

            patient_appointments[patient_id].append(
                {
                    "id": str(appt.id),
                    "date": appt.appointment_date.isoformat(),
                    "type": (
                        appt.appointment_type.name
                        if hasattr(appt, "appointment_type")
                        else None
                    ),
                    "status": appt.status.name if hasattr(appt, "status") else None,
                }
            )

        # Get patient details for each patient with appointments
        result = []
        for patient_id, appointments in patient_appointments.items():
            patient = await self.patient_repository.get_by_id(UUID(patient_id))
            if patient:
                result.append(
                    {
                        "patient": {
                            "id": str(patient.id),
                            "name": f"{patient.first_name} {patient.last_name}",
                            "date_of_birth": patient.date_of_birth.isoformat(),
                        },
                        "appointments": appointments,
                    }
                )

        return result

    async def archive_patient(self, patient_id: UUID) -> bool:
        """
        Archive a patient record (soft delete)

        Args:
            patient_id: UUID of the patient

        Returns:
            True if the patient was archived

        Raises:
            ValidationError: If the patient doesn't exist
        """
        # Retrieve the patient
        patient = await self.patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValidationError(f"Patient with ID {patient_id} does not exist")

        # Archive patient
        if hasattr(patient, "archive"):
            patient.archive()
            await self.patient_repository.update(patient)
            return True
        else:
            # Fallback if archive method doesn't exist
            patient.is_active = False
            await self.patient_repository.update(patient)
            return True

    def _calculate_age(self, birth_date: date) -> int:
        """
        Calculate age from birth date

        Args:
            birth_date: Date of birth

        Returns:
            Age in years
        """
        today = date.today()
        return (
            today.year
            - birth_date.year
            - ((today.month, today.day) < (birth_date.month, birth_date.day))
        )
