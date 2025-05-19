"""
Alert Rule Service Interface.

This interface defines the contract for services that manage biometric alert rules.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class AlertRuleServiceInterface(ABC):
    """
    Interface for alert rule services.

    This interface defines methods for creating, retrieving, updating, and deleting
    biometric alert rules.
    """

    @abstractmethod
    async def create_rule(self, rule_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new alert rule from raw data.

        Args:
            rule_data: Data for the new rule

        Returns:
            The created alert rule

        Raises:
            ApplicationError: If validation fails or creation fails
        """
        pass

    @abstractmethod
    async def get_rule_by_id(self, rule_id: UUID) -> dict[str, Any] | None:
        """
        Get a rule by its ID.

        Args:
            rule_id: ID of the rule to retrieve

        Returns:
            The rule if found, None otherwise

        Raises:
            ApplicationError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_rules(
        self,
        patient_id: UUID | None = None,
        is_active: bool | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Get rules with optional filtering.

        Args:
            patient_id: Optional filter by patient ID
            is_active: Optional filter by active status
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return

        Returns:
            List of rules matching the criteria

        Raises:
            ApplicationError: If retrieval fails
        """
        pass

    @abstractmethod
    async def update_rule(
        self, rule_id: UUID, update_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Update an existing rule.

        Args:
            rule_id: ID of the rule to update
            update_data: Data to update the rule with

        Returns:
            The updated rule or None if not found

        Raises:
            ApplicationError: If validation fails or update fails
        """
        pass

    @abstractmethod
    async def delete_rule(self, rule_id: UUID) -> bool:
        """
        Delete a rule by ID.

        Args:
            rule_id: ID of the rule to delete

        Returns:
            True if deleted, False if not found

        Raises:
            ApplicationError: If deletion fails
        """
        pass

    @abstractmethod
    async def update_rule_active_status(self, rule_id: UUID, is_active: bool) -> bool:
        """
        Update the active status of a rule.

        Args:
            rule_id: ID of the rule to update
            is_active: New active status

        Returns:
            True if updated, False if not found

        Raises:
            ApplicationError: If update fails
        """
        pass
