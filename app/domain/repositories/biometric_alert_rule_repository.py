"""
Repository interface for biometric alert rules.

This module defines the repository pattern for biometric alert rules,
following clean architecture principles with proper domain abstractions.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.biometric_alert_rule import BiometricAlertRule


class BiometricAlertRuleRepository(ABC):
    """
    Repository interface for BiometricAlertRule entities.

    This abstract class defines the repository pattern for biometric alert rules,
    ensuring proper interface segregation and domain abstraction.
    """

    @abstractmethod
    async def get_by_id(self, rule_id: UUID) -> BiometricAlertRule | None:
        """
        Retrieve a BiometricAlertRule by its ID.

        Args:
            rule_id: UUID of the rule to retrieve

        Returns:
            Optional[BiometricAlertRule]: The rule entity if found, None otherwise

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def get_all(self) -> list[BiometricAlertRule]:
        """
        Retrieve all BiometricAlertRules.

        Returns:
            List[BiometricAlertRule]: List of all rule entities

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def get_by_patient_id(self, patient_id: UUID) -> list[BiometricAlertRule]:
        """
        Retrieve all BiometricAlertRules for a specific patient.

        Args:
            patient_id: UUID of the patient

        Returns:
            List[BiometricAlertRule]: List of rule entities for the patient

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def get_by_provider_id(self, provider_id: UUID) -> list[BiometricAlertRule]:
        """
        Retrieve all BiometricAlertRules created by a specific provider.

        Args:
            provider_id: UUID of the provider

        Returns:
            List[BiometricAlertRule]: List of rule entities created by the provider

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def get_all_active(self) -> list[BiometricAlertRule]:
        """
        Retrieve all active BiometricAlertRules.

        Returns:
            List[BiometricAlertRule]: List of active rule entities

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def get_active_rules_for_patient(self, patient_id: UUID) -> list[BiometricAlertRule]:
        """
        Retrieve all active BiometricAlertRules for a specific patient.

        Args:
            patient_id: UUID of the patient

        Returns:
            List[BiometricAlertRule]: List of active rule entities for the patient

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def save(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """
        Save a BiometricAlertRule entity.

        If the rule has an ID and exists, it will be updated.
        If the rule doesn't have an ID or doesn't exist, it will be created.

        Args:
            rule: The rule entity to save

        Returns:
            BiometricAlertRule: The saved rule entity with updated fields

        Raises:
            RepositoryError: If there's an error accessing the repository
            ValidationError: If the rule entity fails validation
        """
        pass

    @abstractmethod
    async def delete(self, rule_id: UUID) -> bool:
        """
        Delete a BiometricAlertRule by its ID.

        Args:
            rule_id: UUID of the rule to delete

        Returns:
            bool: True if the rule was deleted, False if not found

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def count_active_rules(self, patient_id: UUID) -> int:
        """
        Count the number of active rules for a patient.

        Args:
            patient_id: UUID of the patient

        Returns:
            int: Number of active rules for the patient

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def update_active_status(self, rule_id: UUID, is_active: bool) -> bool:
        """
        Update the active status of a rule.

        Args:
            rule_id: UUID of the rule to update
            is_active: New active status

        Returns:
            bool: True if the rule was updated, False if not found

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    # Aliases for backward compatibility - these should forward to the primary methods
    async def get_rules(self) -> list[BiometricAlertRule]:
        """Alias for get_all()"""
        return await self.get_all()

    async def get_rule_by_id(self, rule_id: UUID) -> BiometricAlertRule | None:
        """Alias for get_by_id()"""
        return await self.get_by_id(rule_id)

    async def create_rule(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Alias for save() for new rules"""
        return await self.save(rule)

    async def update_rule(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Alias for save() for existing rules"""
        return await self.save(rule)

    async def delete_rule(self, rule_id: UUID) -> bool:
        """Alias for delete()"""
        return await self.delete(rule_id)
