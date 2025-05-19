"""
Repository interface for biometric alert templates.

This module defines the repository pattern for biometric alert templates,
following clean architecture principles with proper domain abstractions.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class BiometricAlertTemplateRepository(ABC):
    """
    Repository interface for BiometricAlertTemplate entities.

    This abstract class defines the repository pattern for biometric alert templates,
    supporting proper separation of concerns and domain abstraction.
    """

    @abstractmethod
    async def get_all_templates(self) -> list[dict[str, Any]]:
        """
        Retrieve all available biometric alert templates.

        Returns:
            List[Dict[str, Any]]: List of all template definitions

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def get_template_by_id(self, template_id: UUID) -> dict[str, Any] | None:
        """
        Retrieve a template by its ID.

        Args:
            template_id: UUID of the template to retrieve

        Returns:
            Optional[Dict[str, Any]]: The template definition if found, None otherwise

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def get_templates_by_category(self, category: str) -> list[dict[str, Any]]:
        """
        Retrieve templates filtered by category.

        Args:
            category: Category name to filter by

        Returns:
            List[Dict[str, Any]]: List of template definitions in the category

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def get_templates_by_metric_type(
        self, metric_type: str
    ) -> list[dict[str, Any]]:
        """
        Retrieve templates filtered by metric type.

        Args:
            metric_type: Metric type to filter by

        Returns:
            List[Dict[str, Any]]: List of template definitions for the metric type

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass

    @abstractmethod
    async def save_template(self, template: dict[str, Any]) -> dict[str, Any]:
        """
        Save a template definition.

        If the template has an ID and exists, it will be updated.
        If the template doesn't have an ID or doesn't exist, it will be created.

        Args:
            template: The template definition to save

        Returns:
            Dict[str, Any]: The saved template definition with updated fields

        Raises:
            RepositoryError: If there's an error accessing the repository
            ValidationError: If the template definition fails validation
        """
        pass

    @abstractmethod
    async def delete_template(self, template_id: UUID) -> bool:
        """
        Delete a template by its ID.

        Args:
            template_id: UUID of the template to delete

        Returns:
            bool: True if the template was deleted, False if not found

        Raises:
            RepositoryError: If there's an error accessing the repository
        """
        pass
