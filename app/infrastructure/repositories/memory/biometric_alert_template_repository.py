"""
In-memory implementation of the BiometricAlertTemplateRepository.

This module provides a simple memory-based repository for alert templates
with predefined templates for testing and development.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.domain.entities.biometric_alert_rule import AlertPriority, BiometricMetricType, ComparatorOperator
from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)


logger = logging.getLogger(__name__)


# Predefined templates as a seed for the repository
PREDEFINED_TEMPLATES = [
    {
        "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
        "name": "High Heart Rate Alert",
        "description": "Alert when heart rate exceeds threshold",
        "category": "cardiac",
        "metric_type": BiometricMetricType.HEART_RATE,
        "default_threshold": 100.0,
        "operator": ComparatorOperator.GREATER_THAN,
        "default_priority": AlertPriority.MEDIUM,
        "created_at": datetime.utcnow(),
        "conditions": [
            {
                "metric_type": BiometricMetricType.HEART_RATE,
                "operator": ComparatorOperator.GREATER_THAN,
                "threshold_value": 100.0,
                "description": "Heart rate exceeds threshold"
            }
        ],
        "logical_operator": "and"
    },
    {
        "id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
        "name": "Low Heart Rate Alert",
        "description": "Alert when heart rate falls below threshold",
        "category": "cardiac",
        "metric_type": BiometricMetricType.HEART_RATE,
        "default_threshold": 50.0,
        "operator": ComparatorOperator.LESS_THAN,
        "default_priority": AlertPriority.HIGH,
        "created_at": datetime.utcnow(),
        "conditions": [
            {
                "metric_type": BiometricMetricType.HEART_RATE,
                "operator": ComparatorOperator.LESS_THAN,
                "threshold_value": 50.0,
                "description": "Heart rate is too low"
            }
        ],
        "logical_operator": "and"
    },
    {
        "id": uuid.UUID("33333333-3333-3333-3333-333333333333"),
        "name": "Low Oxygen Saturation Alert",
        "description": "Alert when oxygen saturation falls below threshold",
        "category": "respiratory",
        "metric_type": BiometricMetricType.OXYGEN_SATURATION,
        "default_threshold": 92.0,
        "operator": ComparatorOperator.LESS_THAN,
        "default_priority": AlertPriority.CRITICAL,
        "created_at": datetime.utcnow(),
        "conditions": [
            {
                "metric_type": BiometricMetricType.OXYGEN_SATURATION,
                "operator": ComparatorOperator.LESS_THAN,
                "threshold_value": 92.0,
                "description": "Blood oxygen is below safe levels"
            }
        ],
        "logical_operator": "and"
    },
    {
        "id": uuid.UUID("44444444-4444-4444-4444-444444444444"),
        "name": "High Blood Pressure Alert",
        "description": "Alert when blood pressure exceeds threshold",
        "category": "cardiac",
        "metric_type": BiometricMetricType.BLOOD_PRESSURE,
        "default_threshold": 140.0,
        "operator": ComparatorOperator.GREATER_THAN,
        "default_priority": AlertPriority.MEDIUM,
        "created_at": datetime.utcnow(),
        "conditions": [
            {
                "metric_type": BiometricMetricType.BLOOD_PRESSURE,
                "operator": ComparatorOperator.GREATER_THAN,
                "threshold_value": 140.0,
                "description": "Systolic blood pressure is high"
            }
        ],
        "logical_operator": "and"
    },
    {
        "id": uuid.UUID("55555555-5555-5555-5555-555555555555"),
        "name": "High Blood Glucose Alert",
        "description": "Alert when blood glucose exceeds threshold",
        "category": "metabolic",
        "metric_type": BiometricMetricType.BLOOD_GLUCOSE,
        "default_threshold": 180.0,
        "operator": ComparatorOperator.GREATER_THAN,
        "default_priority": AlertPriority.MEDIUM,
        "created_at": datetime.utcnow(),
        "conditions": [
            {
                "metric_type": BiometricMetricType.BLOOD_GLUCOSE,
                "operator": ComparatorOperator.GREATER_THAN,
                "threshold_value": 180.0,
                "description": "Blood glucose is above target range"
            }
        ],
        "logical_operator": "and"
    }
]


class InMemoryBiometricAlertTemplateRepository(BiometricAlertTemplateRepository):
    """
    In-memory implementation of BiometricAlertTemplateRepository.
    
    This class stores templates in memory, providing a simple implementation
    for testing, development, and environments where persistence is not required.
    """
    
    def __init__(self):
        """Initialize with predefined templates."""
        self.templates = {str(template["id"]): template.copy() for template in PREDEFINED_TEMPLATES}
        logger.info(f"Initialized InMemoryBiometricAlertTemplateRepository with {len(self.templates)} templates")

    async def get_all_templates(self) -> List[Dict[str, Any]]:
        """
        Retrieve all available templates.
        
        Returns:
            List of all template definitions
        """
        logger.debug("Getting all templates")
        return list(self.templates.values())

    async def get_template_by_id(self, template_id: UUID) -> Dict[str, Any] | None:
        """
        Retrieve a template by its ID.
        
        Args:
            template_id: UUID of the template to retrieve
            
        Returns:
            The template definition if found, None otherwise
        """
        template_id_str = str(template_id)
        logger.debug(f"Getting template with ID {template_id_str}")
        return self.templates.get(template_id_str)

    async def get_by_id(self, template_id: UUID) -> Dict[str, Any] | None:
        """
        Alias for get_template_by_id for consistency with other repositories.
        
        Args:
            template_id: UUID of the template to retrieve
            
        Returns:
            The template definition if found, None otherwise
        """
        return await self.get_template_by_id(template_id)

    async def get_templates_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Retrieve templates filtered by category.
        
        Args:
            category: Category name to filter by
            
        Returns:
            List of template definitions in the category
        """
        logger.debug(f"Getting templates in category {category}")
        return [
            template for template in self.templates.values()
            if template.get("category", "").lower() == category.lower()
        ]

    async def get_templates_by_metric_type(self, metric_type: str) -> List[Dict[str, Any]]:
        """
        Retrieve templates filtered by metric type.
        
        Args:
            metric_type: Metric type to filter by
            
        Returns:
            List of template definitions for the metric type
        """
        logger.debug(f"Getting templates for metric type {metric_type}")
        return [
            template for template in self.templates.values()
            if str(template.get("metric_type", "")).lower() == metric_type.lower()
        ]

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
        # Check if this is a new template or an update
        template_id = template.get("id")
        if not template_id:
            # New template - generate ID
            template_id = uuid.uuid4()
            template["id"] = template_id
            logger.info(f"Creating new template with ID {template_id}")
        else:
            logger.info(f"Updating template with ID {template_id}")
            
        # Ensure created_at is set
        if "created_at" not in template:
            template["created_at"] = datetime.utcnow()
            
        # Store the template
        self.templates[str(template_id)] = template.copy()
        
        return template

    async def delete_template(self, template_id: UUID) -> bool:
        """
        Delete a template by its ID.
        
        Args:
            template_id: UUID of the template to delete
            
        Returns:
            True if the template was deleted, False if not found
        """
        template_id_str = str(template_id)
        logger.info(f"Deleting template with ID {template_id_str}")
        
        if template_id_str in self.templates:
            del self.templates[template_id_str]
            return True
        return False 