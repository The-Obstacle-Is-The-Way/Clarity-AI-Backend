"""
Clinical Note entity module for the NOVAMIND backend.

This module contains the ClinicalNote entity, which is a core domain entity
representing clinical documentation for patient care in the concierge psychiatry practice.
"""

from dataclasses import dataclass, field
from datetime import datetime
from app.domain.utils.datetime_utils import now_utc, UTC
from app.domain.utils.datetime_utils import UTC
from enum import Enum, auto
from uuid import UUID, uuid4


class NoteType(Enum):
    """Enum representing the possible types of clinical notes"""

    PROGRESS_NOTE = auto()
    INITIAL_EVALUATION = auto()
    MEDICATION_MANAGEMENT = auto()
    THERAPY_SESSION = auto()
    PHONE_CONSULTATION = auto()
    COLLATERAL_CONTACT = auto()
    TREATMENT_PLAN = auto()
    DISCHARGE_SUMMARY = auto()


class NoteStatus(Enum):
    """Enum representing the possible statuses of clinical notes"""

    DRAFT = auto()
    COMPLETED = auto()
    SIGNED = auto()
    AMENDED = auto()
    LOCKED = auto()


@dataclass
class DiagnosisEntry:
    """Value object for a diagnosis in a clinical note"""

    code: str  # ICD-10 or DSM-5 code
    description: str
    primary: bool = False
    notes: str | None = None
    date_diagnosed: datetime = field(default_factory=now_utc)


@dataclass
class MedicationEntry:
    """Value object for a medication entry in a clinical note"""

    name: str
    dosage: str
    frequency: str
    start_date: datetime
    end_date: datetime | None = None
    prescriber_id: UUID | None = None
    reason: str | None = None
    notes: str | None = None


@dataclass
class ClinicalNote:
    """
    ClinicalNote entity representing clinical documentation for patient care.

    This is a rich domain entity containing business logic related to clinical documentation.
    It follows DDD principles, is framework-independent, and adheres to HIPAA compliance requirements.
    """

    patient_id: UUID
    provider_id: UUID
    note_type: NoteType
    content: str
    appointment_id: UUID | None = None
    id: UUID = field(default_factory=uuid4)
    status: NoteStatus = NoteStatus.DRAFT
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)
    signed_at: datetime | None = None
    diagnoses: list[DiagnosisEntry] = field(default_factory=list)
    medications: list[MedicationEntry] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    metadata: dict[str, str] = field(default_factory=dict)
    version: int = 1
    previous_versions: list[UUID] = field(default_factory=list)

    @property
    def is_signed(self) -> bool:
        """Check if the note has been signed"""
        return self.status in [NoteStatus.SIGNED, NoteStatus.LOCKED]

    @property
    def is_locked(self) -> bool:
        """Check if the note is locked (cannot be modified)"""
        return self.status == NoteStatus.LOCKED

    def update_content(self, new_content: str) -> None:
        """
        Update the content of the note

        Args:
            new_content: The new content for the note

        Raises:
            ValueError: If the note is locked
        """
        if self.is_locked:
            raise ValueError("Cannot modify a locked note")

        self.content = new_content
        self.updated_at = datetime.now(UTC)

        # If the note was signed, change status to amended
        if self.status == NoteStatus.SIGNED:
            self.status = NoteStatus.AMENDED

    def sign(self, provider_id: UUID) -> None:
        """
        Sign the clinical note

        Args:
            provider_id: The ID of the provider signing the note

        Raises:
            ValueError: If the note is already locked or if the signer is not the note's provider
        """
        if self.is_locked:
            raise ValueError("Cannot sign a locked note")

        if provider_id != self.provider_id:
            raise ValueError("Only the note's provider can sign it")

        self.status = NoteStatus.SIGNED
        self.signed_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)

    def lock(self) -> None:
        """
        Lock the note to prevent further modifications

        Raises:
            ValueError: If the note is not signed
        """
        if self.status != NoteStatus.SIGNED and self.status != NoteStatus.AMENDED:
            raise ValueError("Only signed or amended notes can be locked")

        self.status = NoteStatus.LOCKED
        self.updated_at = datetime.now(UTC)

    def add_diagnosis(self, diagnosis: DiagnosisEntry) -> None:
        """
        Add a diagnosis to the note

        Args:
            diagnosis: The diagnosis to add

        Raises:
            ValueError: If the note is locked
        """
        if self.is_locked:
            raise ValueError("Cannot modify a locked note")

        self.diagnoses.append(diagnosis)
        self.updated_at = datetime.now(UTC)

    def add_medication(self, medication: MedicationEntry) -> None:
        """
        Add a medication entry to the note

        Args:
            medication: The medication entry to add

        Raises:
            ValueError: If the note is locked
        """
        if self.is_locked:
            raise ValueError("Cannot modify a locked note")

        self.medications.append(medication)
        self.updated_at = datetime.now(UTC)

    def create_new_version(self) -> "ClinicalNote":
        """
        Create a new version of this clinical note

        Returns:
            A new ClinicalNote instance with incremented version number

        Raises:
            ValueError: If the note is not signed or locked
        """
        if not self.is_signed:
            raise ValueError("Only signed notes can be versioned")

        # Create a new note with the same data but new ID and version
        new_note = ClinicalNote(
            patient_id=self.patient_id,
            provider_id=self.provider_id,
            note_type=self.note_type,
            content=self.content,
            appointment_id=self.appointment_id,
            status=NoteStatus.DRAFT,
            diagnoses=self.diagnoses.copy(),
            medications=self.medications.copy(),
            tags=self.tags.copy(),
            metadata=self.metadata.copy(),
            version=self.version + 1,
            previous_versions=self.previous_versions + [self.id],
        )

        return new_note

    def add_tag(self, tag: str) -> None:
        """
        Add a tag to the note

        Args:
            tag: The tag to add

        Raises:
            ValueError: If the note is locked
        """
        if self.is_locked:
            raise ValueError("Cannot modify a locked note")

        self.tags.add(tag)
        self.updated_at = datetime.now(UTC)

    def remove_tag(self, tag: str) -> None:
        """
        Remove a tag from the note

        Args:
            tag: The tag to remove

        Raises:
            ValueError: If the note is locked
        """
        if self.is_locked:
            raise ValueError("Cannot modify a locked note")

        if tag in self.tags:
            self.tags.remove(tag)
            self.updated_at = datetime.now(UTC)

    def has_primary_diagnosis(self) -> bool:
        """
        Check if the note has a primary diagnosis

        Returns:
            True if the note has a primary diagnosis, False otherwise
        """
        return any(diagnosis.primary for diagnosis in self.diagnoses)

    def get_primary_diagnosis(self) -> DiagnosisEntry | None:
        """
        Get the primary diagnosis from the note

        Returns:
            The primary diagnosis or None if no primary diagnosis exists
        """
        for diagnosis in self.diagnoses:
            if diagnosis.primary:
                return diagnosis
        return None
