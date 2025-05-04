"""
Clinical Documentation service module for the NOVAMIND backend.

This module contains the ClinicalDocumentationService, which encapsulates complex business logic
related to clinical notes and documentation in the concierge psychiatry practice.
"""

from datetime import datetime
from uuid import UUID

from app.domain.entities.clinical_note import (
    ClinicalNote,
    DiagnosisEntry,
    MedicationEntry,
    NoteStatus,
    NoteType,
)
from app.domain.repositories.appointment_repository import AppointmentRepository
from app.domain.repositories.clinical_note_repository import ClinicalNoteRepository
from app.domain.repositories.patient_repository import PatientRepository
from app.domain.utils.datetime_utils import UTC


class UnauthorizedAccessError(Exception):
    """Exception raised when a user attempts to access or modify a note they're not authorized for"""

    pass


class ClinicalDocumentationService:
    """
    Service for managing clinical documentation in the concierge psychiatry practice.

    This service encapsulates complex business logic related to clinical notes,
    diagnoses, and documentation workflows while ensuring HIPAA compliance.
    """

    def __init__(
        self,
        clinical_note_repository: ClinicalNoteRepository,
        patient_repository: PatientRepository,
        appointment_repository: AppointmentRepository,
    ):
        """
        Initialize the clinical documentation service

        Args:
            clinical_note_repository: Repository for clinical note data access
            patient_repository: Repository for patient data access
            appointment_repository: Repository for appointment data access
        """
        self._note_repo = clinical_note_repository
        self._patient_repo = patient_repository
        self._appointment_repo = appointment_repository

        # Define standard note templates by type
        self._note_templates: dict[NoteType, str] = {
            NoteType.INITIAL_EVALUATION: (
                "# INITIAL PSYCHIATRIC EVALUATION\n\n"
                "## IDENTIFYING INFORMATION\n\n"
                "## CHIEF COMPLAINT\n\n"
                "## HISTORY OF PRESENT ILLNESS\n\n"
                "## PAST PSYCHIATRIC HISTORY\n\n"
                "## MEDICAL HISTORY\n\n"
                "## FAMILY HISTORY\n\n"
                "## SOCIAL HISTORY\n\n"
                "## SUBSTANCE USE HISTORY\n\n"
                "## MENTAL STATUS EXAMINATION\n\n"
                "## ASSESSMENT\n\n"
                "## DIAGNOSIS\n\n"
                "## TREATMENT PLAN\n\n"
            ),
            NoteType.PROGRESS_NOTE: (
                "# PSYCHIATRIC PROGRESS NOTE\n\n"
                "## SUBJECTIVE\n\n"
                "## OBJECTIVE\n\n"
                "## ASSESSMENT\n\n"
                "## PLAN\n\n"
            ),
            NoteType.MEDICATION_MANAGEMENT: (
                "# MEDICATION MANAGEMENT NOTE\n\n"
                "## CURRENT MEDICATIONS\n\n"
                "## MEDICATION EFFICACY\n\n"
                "## SIDE EFFECTS\n\n"
                "## MEDICATION CHANGES\n\n"
                "## PLAN\n\n"
            ),
            NoteType.THERAPY_SESSION: (
                "# THERAPY SESSION NOTE\n\n"
                "## SESSION FOCUS\n\n"
                "## INTERVENTIONS\n\n"
                "## PATIENT RESPONSE\n\n"
                "## ASSESSMENT\n\n"
                "## PLAN\n\n"
            ),
        }

    async def create_note(
        self,
        patient_id: UUID,
        provider_id: UUID,
        note_type: NoteType,
        appointment_id: UUID | None = None,
        content: str | None = None,
    ) -> ClinicalNote:
        """
        Create a new clinical note

        Args:
            patient_id: UUID of the patient
            provider_id: UUID of the provider creating the note
            note_type: Type of clinical note
            appointment_id: Optional UUID of the associated appointment
            content: Optional content for the note (if not provided, a template will be used)

        Returns:
            The created clinical note entity

        Raises:
            ValueError: If the note data is invalid
        """
        # Verify patient exists
        patient = await self._patient_repo.get_by_id(patient_id)
        if not patient:
            raise ValueError(f"Patient with ID {patient_id} does not exist")

        # Verify appointment exists if provided
        if appointment_id:
            appointment = await self._appointment_repo.get_by_id(appointment_id)
            if not appointment:
                raise ValueError(f"Appointment with ID {appointment_id} does not exist")

            # Verify the appointment belongs to the patient
            if appointment.patient_id != patient_id:
                raise ValueError("Appointment does not belong to the specified patient")

        # Use template content if none provided
        if content is None:
            content = self._note_templates.get(
                note_type, "# CLINICAL NOTE\n\n## CONTENT\n\n"
            )

        # Create clinical note
        note = ClinicalNote(
            patient_id=patient_id,
            provider_id=provider_id,
            note_type=note_type,
            content=content,
            appointment_id=appointment_id,
            status=NoteStatus.DRAFT,
        )

        # Save to repository
        return await self._note_repo.create(note)

    async def update_note_content(
        self, note_id: UUID, new_content: str, provider_id: UUID
    ) -> ClinicalNote:
        """
        Update the content of a clinical note

        Args:
            note_id: UUID of the note to update
            new_content: New content for the note
            provider_id: UUID of the provider making the update

        Returns:
            The updated clinical note entity

        Raises:
            ValueError: If the note cannot be updated
            UnauthorizedAccessError: If the provider is not authorized to update the note
        """
        # Retrieve the note
        note = await self._note_repo.get_by_id(note_id)
        if not note:
            raise ValueError(f"Clinical note with ID {note_id} does not exist")

        # Check authorization
        if note.provider_id != provider_id:
            raise UnauthorizedAccessError("Only the note's provider can update it")

        # Update the content
        note.update_content(new_content)

        # Save to repository
        return await self._note_repo.update(note)

    async def sign_note(self, note_id: UUID, provider_id: UUID) -> ClinicalNote:
        """
        Sign a clinical note

        Args:
            note_id: UUID of the note to sign
            provider_id: UUID of the provider signing the note

        Returns:
            The updated clinical note entity

        Raises:
            ValueError: If the note cannot be signed
            UnauthorizedAccessError: If the provider is not authorized to sign the note
        """
        # Retrieve the note
        note = await self._note_repo.get_by_id(note_id)
        if not note:
            raise ValueError(f"Clinical note with ID {note_id} does not exist")

        # Sign the note
        note.sign(provider_id)

        # Save to repository
        return await self._note_repo.update(note)

    async def lock_note(self, note_id: UUID, provider_id: UUID) -> ClinicalNote:
        """
        Lock a clinical note to prevent further modifications

        Args:
            note_id: UUID of the note to lock
            provider_id: UUID of the provider locking the note

        Returns:
            The updated clinical note entity

        Raises:
            ValueError: If the note cannot be locked
            UnauthorizedAccessError: If the provider is not authorized to lock the note
        """
        # Retrieve the note
        note = await self._note_repo.get_by_id(note_id)
        if not note:
            raise ValueError(f"Clinical note with ID {note_id} does not exist")

        # Check authorization
        if note.provider_id != provider_id:
            raise UnauthorizedAccessError("Only the note's provider can lock it")

        # Lock the note
        note.lock()

        # Save to repository
        return await self._note_repo.update(note)

    async def add_diagnosis(
        self,
        note_id: UUID,
        code: str,
        description: str,
        provider_id: UUID,
        primary: bool = False,
        notes: str | None = None,
    ) -> ClinicalNote:
        """
        Add a diagnosis to a clinical note

        Args:
            note_id: UUID of the note
            code: ICD-10 or DSM-5 code
            description: Description of the diagnosis
            provider_id: UUID of the provider adding the diagnosis
            primary: Whether this is the primary diagnosis
            notes: Optional additional notes about the diagnosis

        Returns:
            The updated clinical note entity

        Raises:
            ValueError: If the diagnosis data is invalid
            UnauthorizedAccessError: If the provider is not authorized to modify the note
        """
        # Retrieve the note
        note = await self._note_repo.get_by_id(note_id)
        if not note:
            raise ValueError(f"Clinical note with ID {note_id} does not exist")

        # Check authorization
        if note.provider_id != provider_id:
            raise UnauthorizedAccessError("Only the note's provider can modify it")

        # Check if this is set as primary but there's already a primary diagnosis
        if primary and note.has_primary_diagnosis():
            # Remove primary flag from existing primary diagnosis
            for diagnosis in note.diagnoses:
                if diagnosis.primary:
                    diagnosis.primary = False
                    break

        # Create diagnosis entry
        diagnosis = DiagnosisEntry(
            code=code,
            description=description,
            primary=primary,
            notes=notes,
            date_diagnosed=datetime.now(UTC),
        )

        # Add to note
        note.add_diagnosis(diagnosis)

        # Save to repository
        return await self._note_repo.update(note)

    async def add_medication_entry(
        self,
        note_id: UUID,
        name: str,
        dosage: str,
        frequency: str,
        start_date: datetime,
        provider_id: UUID,
        end_date: datetime | None = None,
        reason: str | None = None,
        notes: str | None = None,
    ) -> ClinicalNote:
        """
        Add a medication entry to a clinical note

        Args:
            note_id: UUID of the note
            name: Name of the medication
            dosage: Dosage of the medication
            frequency: Frequency of administration
            start_date: Start date for the medication
            provider_id: UUID of the provider adding the entry
            end_date: Optional end date for the medication
            reason: Optional reason for prescribing
            notes: Optional additional notes

        Returns:
            The updated clinical note entity

        Raises:
            ValueError: If the medication data is invalid
            UnauthorizedAccessError: If the provider is not authorized to modify the note
        """
        # Retrieve the note
        note = await self._note_repo.get_by_id(note_id)
        if not note:
            raise ValueError(f"Clinical note with ID {note_id} does not exist")

        # Check authorization
        if note.provider_id != provider_id:
            raise UnauthorizedAccessError("Only the note's provider can modify it")

        # Create medication entry
        medication = MedicationEntry(
            name=name,
            dosage=dosage,
            frequency=frequency,
            start_date=start_date,
            end_date=end_date,
            prescriber_id=provider_id,
            reason=reason,
            notes=notes,
        )

        # Add to note
        note.add_medication(medication)

        # Save to repository
        return await self._note_repo.update(note)

    async def create_new_version(
        self, note_id: UUID, provider_id: UUID
    ) -> ClinicalNote:
        """
        Create a new version of a clinical note

        Args:
            note_id: UUID of the note to version
            provider_id: UUID of the provider creating the new version

        Returns:
            The new clinical note entity

        Raises:
            ValueError: If the note cannot be versioned
            UnauthorizedAccessError: If the provider is not authorized
        """
        # Retrieve the note
        note = await self._note_repo.get_by_id(note_id)
        if not note:
            raise ValueError(f"Clinical note with ID {note_id} does not exist")

        # Check authorization
        if note.provider_id != provider_id:
            raise UnauthorizedAccessError(
                "Only the note's provider can create a new version"
            )

        # Create new version
        new_note = note.create_new_version()

        # Save to repository
        return await self._note_repo.create(new_note)

    async def get_patient_notes_chronological(
        self, patient_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[ClinicalNote]:
        """
        Get a patient's clinical notes in chronological order

        Args:
            patient_id: UUID of the patient
            limit: Maximum number of notes to return
            offset: Number of notes to skip

        Returns:
            List of clinical note entities in chronological order
        """
        # Verify patient exists
        patient = await self._patient_repo.get_by_id(patient_id)
        if not patient:
            raise ValueError(f"Patient with ID {patient_id} does not exist")

        # Get notes for patient
        notes = await self._note_repo.list_by_patient(patient_id, limit, offset)

        # Sort by created_at date
        notes.sort(key=lambda x: x.created_at)

        return notes

    async def search_notes(
        self,
        query: str,
        patient_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ClinicalNote]:
        """
        Search clinical notes by content

        Args:
            query: The search query
            patient_id: Optional UUID of the patient to filter by
            limit: Maximum number of notes to return
            offset: Number of notes to skip

        Returns:
            List of matching clinical note entities
        """
        # If patient_id provided, verify patient exists
        if patient_id:
            patient = await self._patient_repo.get_by_id(patient_id)
            if not patient:
                raise ValueError(f"Patient with ID {patient_id} does not exist")

        # Search notes
        return await self._note_repo.search_by_content(query, patient_id, limit, offset)

    async def get_notes_by_diagnosis_code(
        self, code: str, limit: int = 100, offset: int = 0
    ) -> list[ClinicalNote]:
        """
        Get clinical notes that contain a specific diagnosis code

        Args:
            code: The ICD-10 or DSM-5 code to search for
            limit: Maximum number of notes to return
            offset: Number of notes to skip

        Returns:
            List of matching clinical note entities
        """
        # Get all notes (this is inefficient, but for demonstration)
        # In a real implementation, this would be a specialized repository method
        all_notes = []
        batch_size = 100
        batch_offset = 0

        while True:
            batch = await self._note_repo.list_by_status(
                NoteStatus.SIGNED, batch_size, batch_offset
            )
            if not batch:
                break

            all_notes.extend(batch)
            batch_offset += batch_size

            if len(batch) < batch_size:
                break

        # Filter notes that contain the diagnosis code
        matching_notes = []
        for note in all_notes:
            for diagnosis in note.diagnoses:
                if diagnosis.code == code:
                    matching_notes.append(note)
                    break

        # Apply pagination
        start_idx = min(offset, len(matching_notes))
        end_idx = min(start_idx + limit, len(matching_notes))

        return matching_notes[start_idx:end_idx]
