"""
Alert Rule Template Service Interface.

This interface defines the contract for services that manage biometric alert rule templates.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class AlertRuleTemplateServiceInterface(ABC):
    """
    Interface for alert rule template services.

    This interface defines methods for retrieving and managing
    biometric alert rule templates.
    """

    @abstractmethod
    async def get_all_templates(self) -> list[dict[str, Any]]:
        """
        Get all available alert rule templates.

        Returns:
            List of template definitions
        """
        pass

    @abstractmethod
    async def get_template_by_id(self, template_id: str) -> dict[str, Any] | None:
        """
        Get a specific template by ID or code.

        Args:
            template_id: Unique identifier or code for the template

        Returns:
            Template definition if found, None otherwise
        """
        pass

    @abstractmethod
    async def apply_template(
        self,
        template_id: str,
        patient_id: UUID,
        customization: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Apply a template to create a rule for a specific patient.

        Args:
            template_id: ID or code of the template to apply
            patient_id: ID of the patient to create the rule for
            customization: Optional customization for the template parameters

        Returns:
            The created rule data

        Raises:
            ApplicationError: If template not found or application fails
        """
        pass
