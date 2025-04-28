"""
Clinical Note repository interface for the NOVAMIND backend.

This module defines the interface for clinical note data access operations.
Following the Dependency Inversion Principle, the domain layer depends on
this abstraction rather than concrete implementations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.domain.entities.clinical_note import ClinicalNote, NoteStatus, NoteType


class ClinicalNoteRepository(ABC):
    """
    Repository interface for ClinicalNote entity operations.

    This abstract class defines the contract that any clinical note repository
    implementation must fulfill, ensuring the domain layer remains
    independent of data access technologies.
    """

    @abstractmethod
    async def create(self, note: ClinicalNote) -> ClinicalNote:
        """
        Create a new clinical note record

        Args:
            note: The clinical note entity to create

        Returns:
            The created clinical note with any system-generated fields populated

        Raises:
            RepositoryError: If there's an error during creation
        """
        pass

    @abstractmethod
    async def get_by_id(self, note_id: UUID) -> ClinicalNote | None:
        """
        Retrieve a clinical note by ID

        Args:
            note_id: The UUID of the clinical note to retrieve

        Returns:
            The clinical note entity if found, None otherwise

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def update(self, note: ClinicalNote) -> ClinicalNote:
        """
        Update an existing clinical note record

        Args:
            note: The clinical note entity with updated fields

        Returns:
            The updated clinical note entity

        Raises:
            RepositoryError: If there's an error during update
            EntityNotFoundError: If the clinical note doesn't exist
        """
        pass

    @abstractmethod
    async def delete(self, note_id: UUID) -> bool:
        """
        Delete a clinical note record

        Args:
            note_id: The UUID of the clinical note to delete

        Returns:
            True if the clinical note was deleted, False otherwise

        Raises:
            RepositoryError: If there's an error during deletion
        """
        pass

    @abstractmethod
    async def list_by_patient(
        self, patient_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[ClinicalNote]:
        """
        List all clinical notes for a specific patient with pagination

        Args:
            patient_id: The UUID of the patient
            limit: Maximum number of notes to return
            offset: Number of notes to skip

        Returns:
            List of clinical note entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_by_provider(
        self, provider_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[ClinicalNote]:
        """
        List all clinical notes created by a specific provider with pagination

        Args:
            provider_id: The UUID of the provider
            limit: Maximum number of notes to return
            offset: Number of notes to skip

        Returns:
            List of clinical note entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_by_appointment(self, appointment_id: UUID) -> list[ClinicalNote]:
        """
        List all clinical notes associated with a specific appointment

        Args:
            appointment_id: The UUID of the appointment

        Returns:
            List of clinical note entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_by_status(
        self, status: NoteStatus, limit: int = 100, offset: int = 0
    ) -> list[ClinicalNote]:
        """
        List all clinical notes with a specific status

        Args:
            status: The note status to filter by
            limit: Maximum number of notes to return
            offset: Number of notes to skip

        Returns:
            List of clinical note entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_by_type(
        self, note_type: NoteType, limit: int = 100, offset: int = 0
    ) -> list[ClinicalNote]:
        """
        List all clinical notes of a specific type

        Args:
            note_type: The note type to filter by
            limit: Maximum number of notes to return
            offset: Number of notes to skip

        Returns:
            List of clinical note entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        patient_id: UUID | None = None,
    ) -> list[ClinicalNote]:
        """
        List all clinical notes within a date range, optionally filtered by patient

        Args:
            start_date: The start of the date range
            end_date: The end of the date range
            patient_id: Optional UUID of the patient to filter by

        Returns:
            List of clinical note entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def search_by_content(
        self,
        query: str,
        patient_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ClinicalNote]:
        """
        Search clinical notes by content, optionally filtered by patient

        Args:
            query: The search query
            patient_id: Optional UUID of the patient to filter by
            limit: Maximum number of notes to return
            offset: Number of notes to skip

        Returns:
            List of matching clinical note entities

        Raises:
            RepositoryError: If there's an error during search
        """
        pass

    @abstractmethod
    async def get_latest_by_patient(self, patient_id: UUID) -> ClinicalNote | None:
        """
        Get the most recent clinical note for a specific patient

        Args:
            patient_id: The UUID of the patient

        Returns:
            The most recent clinical note entity if found, None otherwise

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def count_by_patient(self, patient_id: UUID) -> int:
        """
        Count all clinical notes for a specific patient

        Args:
            patient_id: The UUID of the patient

        Returns:
            The total number of clinical notes for the patient

        Raises:
            RepositoryError: If there's an error during counting
        """
        pass
