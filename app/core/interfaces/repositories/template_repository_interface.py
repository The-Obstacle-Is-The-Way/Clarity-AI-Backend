"""
Template Repository Interface.

Defines the interface for repositories that manage templates for various entities.
"""

import uuid
from abc import ABC, abstractmethod
from typing import Any

from app.domain.entities.biometric_rule import BiometricAlertRule


class ITemplateRepository(ABC):
    """Interface for template repositories."""

    @abstractmethod
    async def get_all_templates(self) -> list[BiometricAlertRule]:
        """
        Get all available templates.

        Returns:
            List of template entities

        Raises:
            RepositoryError: If an error occurs during the operation
        """
        pass

    @abstractmethod
    async def get_template_by_id(self, template_id: uuid.UUID) -> BiometricAlertRule | None:
        """
        Get a template by its ID.

        Args:
            template_id: The unique identifier of the template

        Returns:
            The template entity if found, None otherwise

        Raises:
            RepositoryError: If an error occurs during the operation
        """
        pass

    @abstractmethod
    async def create_template(self, template_data: dict[str, Any]) -> BiometricAlertRule:
        """
        Create a new template.

        Args:
            template_data: Dictionary containing template data

        Returns:
            The created template entity

        Raises:
            ValidationError: If the template data is invalid
            RepositoryError: If an error occurs during the operation
        """
        pass

    @abstractmethod
    async def update_template(
        self, template_id: uuid.UUID, template_data: dict[str, Any]
    ) -> BiometricAlertRule | None:
        """
        Update an existing template.

        Args:
            template_id: The unique identifier of the template to update
            template_data: Dictionary containing updated template data

        Returns:
            The updated template entity if found, None otherwise

        Raises:
            ValidationError: If the template data is invalid
            RepositoryError: If an error occurs during the operation
        """
        pass

    @abstractmethod
    async def delete_template(self, template_id: uuid.UUID) -> bool:
        """
        Delete a template.

        Args:
            template_id: The unique identifier of the template to delete

        Returns:
            True if the template was deleted, False if not found

        Raises:
            RepositoryError: If an error occurs during the operation
        """
        pass
