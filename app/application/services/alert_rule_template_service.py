"""
Alert Rule Template Service Implementation.

This service provides functionality for managing biometric alert rule templates,
following clean architecture principles.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.core.exceptions import ApplicationError, ErrorCode
from app.core.interfaces.services.alert_rule_template_service_interface import AlertRuleTemplateServiceInterface
from app.domain.entities.biometric_alert_rule import (
    AlertPriority,
    BiometricAlertRule,
    BiometricMetricType,
    ComparatorOperator,
    RuleCondition,
    RuleLogicalOperator
)
from app.domain.repositories.biometric_alert_template_repository import BiometricAlertTemplateRepository
from app.domain.repositories.biometric_alert_rule_repository import BiometricAlertRuleRepository

logger = logging.getLogger(__name__)

class AlertRuleTemplateService(AlertRuleTemplateServiceInterface):
    """
    Service for managing biometric alert rule templates.
    
    This service implements application logic for retrieving templates
    and applying them to create patient-specific alert rules.
    """
    
    def __init__(
        self,
        template_repository: BiometricAlertTemplateRepository,
        rule_repository: BiometricAlertRuleRepository
    ):
        """
        Initialize the service with required repositories.
        
        Args:
            template_repository: Repository for alert templates
            rule_repository: Repository for alert rules
        """
        self.template_repository = template_repository
        self.rule_repository = rule_repository
    
    async def get_all_templates(self) -> List[dict[str, Any]]:
        """
        Get all available alert rule templates.
        
        Returns:
            List of template definitions
            
        Raises:
            ApplicationError: If retrieval fails
        """
        try:
            templates = await self.template_repository.get_all_templates()
            return [self._to_dict(template) for template in templates]
        except Exception as e:
            logger.error(f"Failed to get templates: {str(e)}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to retrieve templates: {str(e)}"
            )
    
    async def get_template_by_id(self, template_id: str) -> Optional[dict[str, Any]]:
        """
        Get a specific template by ID or code.
        
        Args:
            template_id: Unique identifier or code for the template
            
        Returns:
            Template definition if found, None otherwise
            
        Raises:
            ApplicationError: If retrieval fails
        """
        try:
            # Try parsing as UUID first
            try:
                uuid_template_id = uuid.UUID(template_id)
                template = await self.template_repository.get_template_by_id(uuid_template_id)
            except ValueError:
                # If not a valid UUID, try by code/name
                templates = await self.template_repository.get_templates_by_category(template_id)
                template = templates[0] if templates else None
                
            if template:
                return self._to_dict(template)
            return None
            
        except Exception as e:
            logger.error(f"Failed to get template {template_id}: {str(e)}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to retrieve template: {str(e)}"
            )
    
    async def apply_template(
        self,
        template_id: str,
        patient_id: UUID,
        customization: dict[str, Any] | None = None
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
        if customization is None:
            customization = {}
            
        logger.info(f"Applying template {template_id} for patient {patient_id}")
        
        # Get the template
        template_data = await self.get_template_by_id(template_id)
        if not template_data:
            logger.error(f"Template {template_id} not found")
            raise ApplicationError(
                code=ErrorCode.NOT_FOUND,
                message=f"Template {template_id} not found"
            )
        
        try:
            # Extract customization
            threshold_value = customization.get("threshold_value")
            priority_str = customization.get("priority", "medium").lower()
            
            try:
                priority = getattr(AlertPriority, priority_str.upper())
            except AttributeError:
                logger.warning(f"Invalid priority '{priority_str}', using default MEDIUM")
                priority = AlertPriority.MEDIUM
            
            # Create conditions based on template
            conditions = []
            for template_condition in template_data.get("conditions", []):
                metric_type = template_condition.get("metric_type")
                operator = template_condition.get("operator")
                
                # Apply threshold override if provided and matches the condition
                condition_threshold = threshold_value if threshold_value is not None else template_condition.get("threshold_value")
                
                condition = RuleCondition(
                    metric_type=metric_type,
                    operator=operator,
                    threshold_value=condition_threshold,
                    description=template_condition.get("description")
                )
                conditions.append(condition)
            
            # Create the rule
            rule = BiometricAlertRule(
                name=template_data.get("name", "Alert Rule"),
                description=template_data.get("description"),
                patient_id=patient_id,
                conditions=conditions,
                logical_operator=template_data.get("logical_operator", RuleLogicalOperator.AND),
                priority=priority,
                is_active=True,
                template_id=UUID(template_id) if template_id and len(template_id) == 36 else None
            )
            
            # Save to repository
            created_rule = await self.rule_repository.save(rule)
            logger.info(f"Created rule {created_rule.id} from template {template_id}")
            
            # Return as dictionary
            return self._to_dict(created_rule)
            
        except ApplicationError:
            # Re-raise application errors
            raise
        except Exception as e:
            logger.error(f"Failed to apply template: {str(e)}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to apply template: {str(e)}"
            )
    
    def _to_dict(self, entity: Any) -> dict[str, Any]:
        """
        Convert an entity to a dictionary.
        
        Args:
            entity: Entity to convert
            
        Returns:
            Dictionary representation of the entity
        """
        if hasattr(entity, "dict"):
            # For pydantic models
            return entity.dict()
        elif hasattr(entity, "model_dump"):
            # For newer pydantic v2 models
            return entity.model_dump()
        elif hasattr(entity, "__dict__"):
            # For regular classes
            return {k: v for k, v in entity.__dict__.items() if not k.startswith("_")}
        else:
            # For dictionary-like objects
            return dict(entity)
