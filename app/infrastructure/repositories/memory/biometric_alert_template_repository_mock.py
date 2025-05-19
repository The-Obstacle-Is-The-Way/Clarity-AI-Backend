"""
In-Memory Mock Biometric Alert Template Repository Module.

This module provides a mock implementation of the template repository interface
for biometric alert templates. It's useful for testing and development.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)


class MockBiometricAlertTemplateRepository(BiometricAlertTemplateRepository):
    """
    Mock implementation of BiometricAlertTemplateRepository for testing.

    This repository returns predefined template data for testing purposes.
    """

    def __init__(self, session: AsyncSession = None):
        """Initialize the repository with predefined templates."""
        self._templates = self._get_predefined_templates()

    def _get_predefined_templates(self) -> List[Dict[str, Any]]:
        """Return a list of predefined templates for testing."""
        return [
            {
                "id": "high_heart_rate",
                "name": "High Heart Rate Alert",
                "description": "Alert when heart rate exceeds threshold",
                "category": "cardiac",
                "conditions": [
                    {
                        "metric_name": "heart_rate",
                        "operator": "GREATER_THAN",
                        "threshold": 100,
                        "unit": "bpm",
                    }
                ],
                "priority": "MEDIUM",
            },
            {
                "id": "low_blood_pressure",
                "name": "Low Blood Pressure Alert",
                "description": "Alert when blood pressure falls below threshold",
                "category": "cardiac",
                "conditions": [
                    {
                        "metric_name": "systolic_bp",
                        "operator": "LESS_THAN",
                        "threshold": 90,
                        "unit": "mmHg",
                    }
                ],
                "priority": "HIGH",
            },
            {
                "id": "high_glucose",
                "name": "High Blood Glucose Alert",
                "description": "Alert when blood glucose exceeds threshold",
                "category": "metabolic",
                "conditions": [
                    {
                        "metric_name": "blood_glucose",
                        "operator": "GREATER_THAN",
                        "threshold": 180,
                        "unit": "mg/dL",
                    }
                ],
                "priority": "MEDIUM",
            },
        ]

    async def get_all_templates(self) -> List[Dict[str, Any]]:
        """
        Retrieve all available biometric alert templates.

        Returns:
            List of all template definitions
        """
        return self._templates

    async def get_template_by_id(self, template_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Retrieve a template by its ID.

        Args:
            template_id: UUID of the template to retrieve

        Returns:
            The template definition if found, None otherwise
        """
        template_id_str = str(template_id)
        for template in self._templates:
            if str(template["id"]) == template_id_str:
                return template
        return None

    async def get_templates_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Retrieve templates filtered by category.

        Args:
            category: Category name to filter by

        Returns:
            List of template definitions in the category
        """
        return [
            t
            for t in self._templates
            if t.get("category", "").lower() == category.lower()
        ]

    async def get_templates_by_metric_type(
        self, metric_type: str
    ) -> List[Dict[str, Any]]:
        """
        Retrieve templates filtered by metric type.

        Args:
            metric_type: Metric type to filter by

        Returns:
            List of template definitions for the metric type
        """
        result = []
        for template in self._templates:
            for condition in template.get("conditions", []):
                if condition.get("metric_name", "").lower() == metric_type.lower():
                    result.append(template)
                    break
        return result

    async def save_template(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """
        Save a template definition.

        If the template has an ID and exists, it will be updated.
        If the template doesn't have an ID or doesn't exist, it will be created.

        Args:
            template: The template definition to save

        Returns:
            The saved template definition with updated fields
        """
        # For testing purposes, just return the input
        return template

    async def delete_template(self, template_id: UUID) -> bool:
        """
        Delete a template by its ID.

        Args:
            template_id: UUID of the template to delete

        Returns:
            True if the template was deleted, False if not found
        """
        # For testing purposes, just return True
        return True
