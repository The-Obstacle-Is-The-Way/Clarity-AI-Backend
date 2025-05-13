"""
In-Memory Biometric Alert Template Repository Module.

This module provides an in-memory implementation of the template repository interface
for biometric alert templates. It's useful for testing, development, or when
a persistent storage is not required.
"""

import copy
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.core.domain.entities.biometric import MetricType
from app.core.interfaces.repositories.template_repository_interface import ITemplateRepository
from app.domain.entities.biometric_rule import (
    AlertPriority,
    BiometricAlertRule,
    BiometricRuleCondition,
    LogicalOperator,
    RuleOperator,
)


class InMemoryBiometricAlertTemplateRepository(ITemplateRepository):
    """
    In-memory implementation of biometric alert template repository.
    
    This repository stores all templates in memory and provides predefined
    templates for common biometric alert scenarios.
    """
    
    def __init__(self):
        """Initialize the repository with predefined templates."""
        self._templates: Dict[UUID, BiometricAlertRule] = {}
        self._initialize_predefined_templates()
    
    def _initialize_predefined_templates(self) -> None:
        """Initialize the repository with predefined templates."""
        # Heart rate high template
        hr_high_id = uuid.uuid4()
        hr_high = BiometricAlertRule(
            id=hr_high_id,
            name="High Heart Rate Alert Template",
            description="Template for detecting abnormally high heart rate",
            conditions=[
                BiometricRuleCondition(
                    metric_type=MetricType.HEART_RATE,
                    operator=RuleOperator.GREATER_THAN,
                    threshold_value=100,
                    description="Heart rate above 100 BPM"
                )
            ],
            logical_operator=LogicalOperator.AND,
            priority=AlertPriority.MEDIUM,
            is_active=True,
            is_template=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self._templates[hr_high_id] = hr_high
        
        # Heart rate low template
        hr_low_id = uuid.uuid4()
        hr_low = BiometricAlertRule(
            id=hr_low_id,
            name="Low Heart Rate Alert Template",
            description="Template for detecting abnormally low heart rate",
            conditions=[
                BiometricRuleCondition(
                    metric_type=MetricType.HEART_RATE,
                    operator=RuleOperator.LESS_THAN,
                    threshold_value=50,
                    description="Heart rate below 50 BPM"
                )
            ],
            logical_operator=LogicalOperator.AND,
            priority=AlertPriority.HIGH,
            is_active=True,
            is_template=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self._templates[hr_low_id] = hr_low
        
        # High blood pressure template
        bp_high_id = uuid.uuid4()
        bp_high = BiometricAlertRule(
            id=bp_high_id,
            name="High Blood Pressure Alert Template",
            description="Template for detecting high blood pressure",
            conditions=[
                BiometricRuleCondition(
                    metric_type=MetricType.BLOOD_PRESSURE_SYSTOLIC,
                    operator=RuleOperator.GREATER_THAN,
                    threshold_value=140,
                    description="Systolic pressure above 140 mmHg"
                ),
                BiometricRuleCondition(
                    metric_type=MetricType.BLOOD_PRESSURE_DIASTOLIC,
                    operator=RuleOperator.GREATER_THAN,
                    threshold_value=90,
                    description="Diastolic pressure above 90 mmHg"
                )
            ],
            logical_operator=LogicalOperator.AND,
            priority=AlertPriority.MEDIUM,
            is_active=True,
            is_template=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self._templates[bp_high_id] = bp_high
        
        # Elevated body temperature template
        temp_high_id = uuid.uuid4()
        temp_high = BiometricAlertRule(
            id=temp_high_id,
            name="Fever Alert Template",
            description="Template for detecting elevated body temperature",
            conditions=[
                BiometricRuleCondition(
                    metric_type=MetricType.BODY_TEMPERATURE,
                    operator=RuleOperator.GREATER_THAN,
                    threshold_value=38.0,  # 38°C / 100.4°F
                    description="Body temperature above 38°C (100.4°F)"
                )
            ],
            logical_operator=LogicalOperator.AND,
            priority=AlertPriority.MEDIUM,
            is_active=True,
            is_template=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self._templates[temp_high_id] = temp_high
        
        # Low blood glucose level template
        glucose_low_id = uuid.uuid4()
        glucose_low = BiometricAlertRule(
            id=glucose_low_id,
            name="Hypoglycemia Alert Template",
            description="Template for detecting low blood glucose levels",
            conditions=[
                BiometricRuleCondition(
                    metric_type=MetricType.BLOOD_GLUCOSE,
                    operator=RuleOperator.LESS_THAN,
                    threshold_value=70,  # 70 mg/dL
                    description="Blood glucose below 70 mg/dL"
                )
            ],
            logical_operator=LogicalOperator.AND,
            priority=AlertPriority.HIGH,
            is_active=True,
            is_template=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self._templates[glucose_low_id] = glucose_low
    
    async def get_all_templates(self) -> List[BiometricAlertRule]:
        """
        Get all available templates.
        
        Returns:
            List of all template entities
        """
        return list(self._templates.values())
    
    async def get_template_by_id(self, template_id: UUID) -> Optional[BiometricAlertRule]:
        """
        Get a template by its ID.
        
        Args:
            template_id: The unique identifier of the template
            
        Returns:
            The template entity if found, None otherwise
        """
        return self._templates.get(template_id)
    
    async def create_template(self, template_data: Dict[str, Any]) -> BiometricAlertRule:
        """
        Create a new template.
        
        Args:
            template_data: Dictionary containing template data
            
        Returns:
            The created template entity
            
        Raises:
            ValueError: If the template data is invalid
        """
        # If no ID is provided, generate one
        if "id" not in template_data:
            template_data["id"] = uuid.uuid4()
        
        # Ensure it's marked as a template
        template_data["is_template"] = True
        
        # Set creation and update timestamps
        now = datetime.utcnow()
        template_data["created_at"] = now
        template_data["updated_at"] = now
        
        # Create the template entity
        try:
            template = BiometricAlertRule(**template_data)
        except Exception as e:
            raise ValueError(f"Invalid template data: {str(e)}")
        
        # Store in memory
        self._templates[template.id] = template
        return template
    
    async def update_template(
        self, template_id: UUID, template_data: Dict[str, Any]
    ) -> Optional[BiometricAlertRule]:
        """
        Update an existing template.
        
        Args:
            template_id: The unique identifier of the template to update
            template_data: Dictionary containing updated template data
            
        Returns:
            The updated template entity if found, None otherwise
            
        Raises:
            ValueError: If the template data is invalid
        """
        # Check if template exists
        if template_id not in self._templates:
            return None
        
        # Get existing template and update with new data
        existing_template = self._templates[template_id]
        updated_data = copy.deepcopy(existing_template.__dict__)
        
        # Update fields
        for key, value in template_data.items():
            if key != "id" and hasattr(existing_template, key):  # Don't allow changing ID
                updated_data[key] = value
        
        # Update timestamp
        updated_data["updated_at"] = datetime.utcnow()
        
        # Create updated entity
        try:
            updated_template = BiometricAlertRule(**updated_data)
        except Exception as e:
            raise ValueError(f"Invalid template data: {str(e)}")
        
        # Store updated template
        self._templates[template_id] = updated_template
        return updated_template
    
    async def delete_template(self, template_id: UUID) -> bool:
        """
        Delete a template.
        
        Args:
            template_id: The unique identifier of the template to delete
            
        Returns:
            True if the template was deleted, False if not found
        """
        if template_id in self._templates:
            del self._templates[template_id]
            return True
        return False 