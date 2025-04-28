"""
Medication repository interface for the NOVAMIND backend.

This module defines the interface for medication data access operations.
Following the Dependency Inversion Principle, the domain layer depends on
this abstraction rather than concrete implementations.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.medication import Medication, MedicationStatus, RefillStatus


class MedicationRepository(ABC):
    """
    Repository interface for Medication entity operations.

    This abstract class defines the contract that any medication repository
    implementation must fulfill, ensuring the domain layer remains
    independent of data access technologies.
    """

    @abstractmethod
    async def create(self, medication: Medication) -> Medication:
        """
        Create a new medication record

        Args:
            medication: The medication entity to create

        Returns:
            The created medication with any system-generated fields populated

        Raises:
            RepositoryError: If there's an error during creation
        """
        pass

    @abstractmethod
    async def get_by_id(self, medication_id: UUID) -> Medication | None:
        """
        Retrieve a medication by ID

        Args:
            medication_id: The UUID of the medication to retrieve

        Returns:
            The medication entity if found, None otherwise

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def update(self, medication: Medication) -> Medication:
        """
        Update an existing medication record

        Args:
            medication: The medication entity with updated fields

        Returns:
            The updated medication entity

        Raises:
            RepositoryError: If there's an error during update
            EntityNotFoundError: If the medication doesn't exist
        """
        pass

    @abstractmethod
    async def delete(self, medication_id: UUID) -> bool:
        """
        Delete a medication record

        Args:
            medication_id: The UUID of the medication to delete

        Returns:
            True if the medication was deleted, False otherwise

        Raises:
            RepositoryError: If there's an error during deletion
        """
        pass

    @abstractmethod
    async def list_by_patient(
        self, patient_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[Medication]:
        """
        List all medications for a specific patient with pagination

        Args:
            patient_id: The UUID of the patient
            limit: Maximum number of medications to return
            offset: Number of medications to skip

        Returns:
            List of medication entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_by_provider(
        self, provider_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[Medication]:
        """
        List all medications prescribed by a specific provider with pagination

        Args:
            provider_id: The UUID of the provider
            limit: Maximum number of medications to return
            offset: Number of medications to skip

        Returns:
            List of medication entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_by_status(
        self, status: MedicationStatus, limit: int = 100, offset: int = 0
    ) -> list[Medication]:
        """
        List all medications with a specific status

        Args:
            status: The medication status to filter by
            limit: Maximum number of medications to return
            offset: Number of medications to skip

        Returns:
            List of medication entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_active_by_patient(self, patient_id: UUID) -> list[Medication]:
        """
        List all active medications for a specific patient

        Args:
            patient_id: The UUID of the patient

        Returns:
            List of active medication entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def list_by_refill_status(
        self, refill_status: RefillStatus, limit: int = 100, offset: int = 0
    ) -> list[Medication]:
        """
        List all medications with a specific refill status

        Args:
            refill_status: The refill status to filter by
            limit: Maximum number of medications to return
            offset: Number of medications to skip

        Returns:
            List of medication entities

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def search_by_name(
        self,
        name: str,
        patient_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Medication]:
        """
        Search medications by name, optionally filtered by patient

        Args:
            name: The medication name to search for
            patient_id: Optional UUID of the patient to filter by
            limit: Maximum number of medications to return
            offset: Number of medications to skip

        Returns:
            List of matching medication entities

        Raises:
            RepositoryError: If there's an error during search
        """
        pass

    @abstractmethod
    async def get_medications_needing_refill(self) -> list[Medication]:
        """
        Get all medications that need a refill

        Returns:
            List of medication entities that need a refill

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def get_medications_expiring_soon(self, days: int = 7) -> list[Medication]:
        """
        Get all medications that are expiring within the specified number of days

        Args:
            days: Number of days to look ahead

        Returns:
            List of medication entities expiring soon

        Raises:
            RepositoryError: If there's an error during retrieval
        """
        pass

    @abstractmethod
    async def count_by_patient(self, patient_id: UUID) -> int:
        """
        Count all medications for a specific patient

        Args:
            patient_id: The UUID of the patient

        Returns:
            The total number of medications for the patient

        Raises:
            RepositoryError: If there's an error during counting
        """
        pass
