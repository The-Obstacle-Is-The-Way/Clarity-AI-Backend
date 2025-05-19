"""
Biometric Rule Repository Interface for the Digital Twin Psychiatry Platform.

This module defines the repository interface for storing and retrieving
biometric rules. It follows the Repository pattern to abstract data access
and maintain separation between domain and infrastructure layers.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.biometric_rule import AlertPriority, BiometricRule


class BiometricRuleRepository(ABC):
    """
    Repository interface for biometric rules.

    This interface defines methods for storing, retrieving, and querying
    biometric rules. Implementations will handle the actual persistence
    mechanism (e.g., database, file system).
    """

    @abstractmethod
    async def save(self, rule: BiometricRule) -> BiometricRule:
        """
        Save a biometric rule to the repository.

        Args:
            rule: The biometric rule to save

        Returns:
            The saved biometric rule with any updates (e.g., ID assignment)

        Raises:
            RepositoryError: If there's an error saving the rule
        """
        pass

    @abstractmethod
    async def get_by_id(self, rule_id: UUID) -> BiometricRule | None:
        """
        Retrieve a biometric rule by its ID.

        Args:
            rule_id: ID of the rule to retrieve

        Returns:
            The biometric rule if found, None otherwise

        Raises:
            RepositoryError: If there's an error retrieving the rule
        """
        pass

    @abstractmethod
    async def get_all_active(
        self, patient_id: UUID | None = None, priority: AlertPriority | None = None
    ) -> list[BiometricRule]:
        """
        Retrieve all active biometric rules.

        Args:
            patient_id: Optional patient ID to filter patient-specific rules
            priority: Optional priority level to filter rules

        Returns:
            List of active biometric rules matching the criteria

        Raises:
            RepositoryError: If there's an error retrieving the rules
        """
        pass

    @abstractmethod
    async def get_by_patient_id(self, patient_id: UUID) -> list[BiometricRule]:
        """
        Retrieve biometric rules specific to a patient.

        Args:
            patient_id: ID of the patient

        Returns:
            List of biometric rules for the specified patient

        Raises:
            RepositoryError: If there's an error retrieving the rules
        """
        pass

    @abstractmethod
    async def get_by_provider_id(self, provider_id: UUID) -> list[BiometricRule]:
        """
        Retrieve biometric rules created by a specific provider.

        Args:
            provider_id: ID of the provider

        Returns:
            List of biometric rules created by the specified provider

        Raises:
            RepositoryError: If there's an error retrieving the rules
        """
        pass

    @abstractmethod
    async def update_active_status(
        self, rule_id: UUID, is_active: bool
    ) -> BiometricRule:
        """
        Update the active status of a biometric rule.

        Args:
            rule_id: ID of the rule to update
            is_active: New active status for the rule

        Returns:
            The updated biometric rule

        Raises:
            EntityNotFoundError: If the rule doesn't exist
            RepositoryError: If there's an error updating the rule
        """
        pass

    @abstractmethod
    async def delete(self, rule_id: UUID) -> bool:
        """
        Delete a biometric rule from the repository.

        Args:
            rule_id: ID of the rule to delete

        Returns:
            True if the rule was deleted, False otherwise

        Raises:
            RepositoryError: If there's an error deleting the rule
        """
        pass

    @abstractmethod
    async def count_active_rules(self, patient_id: UUID | None = None) -> int:
        """
        Count active biometric rules.

        Args:
            patient_id: Optional patient ID to count rules for a specific patient

        Returns:
            Number of active rules matching the criteria

        Raises:
            RepositoryError: If there's an error counting the rules
        """
        pass
