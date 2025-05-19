"""
Mock Alert Rule Template Service Implementation.

This module provides a mock implementation of the alert rule template service
for testing purposes.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from app.core.interfaces.services.alert_rule_template_service_interface import AlertRuleTemplateServiceInterface
from app.domain.repositories.biometric_alert_template_repository import BiometricAlertTemplateRepository
from app.domain.repositories.biometric_alert_rule_repository import BiometricAlertRuleRepository


class MockAlertRuleTemplateService(AlertRuleTemplateServiceInterface):
    """
    Mock implementation of alert rule template service for testing.
    
    This service returns predefined template data instead of querying
    the actual repository.
    """
    
    def __init__(
        self,
        template_repository: Optional[BiometricAlertTemplateRepository] = None,
        rule_repository: Optional[BiometricAlertRuleRepository] = None
    ):
        """
        Initialize the mock service.
        
        Args:
            template_repository: Optional template repository (not used in mock)
            rule_repository: Optional rule repository (not used in mock)
        """
        self.template_repository = template_repository
        self.rule_repository = rule_repository
    
    async def get_all_templates(self) -> List[Dict[str, Any]]:
        """
        Get all available alert rule templates.
        
        Returns:
            List of template definitions
        """
        return [
            {
                "template_id": "high_heart_rate",
                "name": "High Heart Rate Template",
                "description": "Alert when heart rate exceeds threshold",
                "category": "cardiac",
                "conditions": [
                    {
                        "metric_name": "heart_rate",
                        "comparator_operator": "greater_than",
                        "threshold_value": 100,
                        "duration_minutes": 5
                    }
                ],
                "logical_operator": "and",
                "default_priority": "medium",
                "customizable_fields": ["threshold_value", "priority"]
            },
            {
                "template_id": "low_blood_pressure",
                "name": "Low Blood Pressure Template",
                "description": "Alert when blood pressure falls below threshold",
                "category": "cardiac",
                "conditions": [
                    {
                        "metric_name": "systolic_bp",
                        "comparator_operator": "less_than",
                        "threshold_value": 90,
                        "duration_minutes": 10
                    }
                ],
                "logical_operator": "and",
                "default_priority": "high",
                "customizable_fields": ["threshold_value", "priority"]
            }
        ]
    
    async def get_template_by_id(self, template_id: str) -> Dict[str, Any] | None:
        """
        Get a specific template by ID or code.
        
        Args:
            template_id: Unique identifier or code for the template
            
        Returns:
            Template definition if found, None otherwise
        """
        templates = await self.get_all_templates()
        for template in templates:
            if str(template.get("template_id")) == str(template_id):
                return template
        return None
    
    async def apply_template(
        self,
        template_id: str,
        patient_id: UUID,
        customization: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """
        Apply a template to create a rule for a specific patient.
        
        Args:
            template_id: ID or code of the template to apply
            patient_id: ID of the patient to create the rule for
            customization: Optional customization for the template parameters
            
        Returns:
            The created rule data
        """
        if customization is None:
            customization = {}
            
        template = await self.get_template_by_id(template_id)
        if not template:
            raise ValueError(f"Template with ID {template_id} not found")
        
        # Create a rule from the template with customizations
        rule = {
            "id": UUID('00000000-0000-0000-0000-000000000001'),  # Mock ID
            "name": customization.get("name", template.get("name")),
            "description": customization.get("description", template.get("description")),
            "patient_id": patient_id,
            "is_active": customization.get("is_active", True),
            "priority": customization.get("priority", template.get("default_priority", "medium")),
            "logical_operator": customization.get("logical_operator", template.get("logical_operator", "and")),
            "conditions": template.get("conditions", []),
            "template_id": template_id,
            "created_at": "2025-05-19T12:00:00Z",
            "updated_at": "2025-05-19T12:00:00Z"
        }
        
        return rule 