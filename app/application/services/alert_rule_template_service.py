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
    Service for managing alert rule templates.
    
    This service implements application logic for retrieving and applying
    biometric alert rule templates, orchestrating domain entities and repositories.
    """
    
    def __init__(
        self,
        template_repository: BiometricAlertTemplateRepository,
        rule_repository: BiometricAlertRuleRepository
    ):
        """
        Initialize the service with required repositories.
        
        Args:
            template_repository: Repository for alert rule templates
            rule_repository: Repository for alert rules
        """
        self.template_repository = template_repository
        self.rule_repository = rule_repository
    
    async def get_all_templates(self) -> List[Dict[str, Any]]:
        """
        Get all available alert rule templates.
        
        Returns:
            List of template definitions
        """
        logger.info("Getting all alert rule templates")
        templates = await self.template_repository.get_all_templates()
        return [self._to_dict(template) for template in templates]
    
    async def get_template_by_id(self, template_id: str) -> Dict[str, Any] | None:
        """
        Get a specific template by ID or code.
        
        Args:
            template_id: Unique identifier or code for the template
            
        Returns:
            Template definition if found, None otherwise
        """
        logger.info(f"Getting template with ID {template_id}")
        template = await self.template_repository.get_template_by_id(template_id)
        if template:
            return self._to_dict(template)
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
            
        Raises:
            ApplicationError: If template not found or application fails
        """
        logger.info(f"Applying template {template_id} for patient {patient_id}")
        
        # Default empty customization if None
        if customization is None:
            customization = {}
            
        # Get the template
        template = await self.template_repository.get_template_by_id(template_id)
        if not template:
            error_msg = f"Template with ID {template_id} not found"
            logger.error(error_msg)
            raise ApplicationError(
                code=ErrorCode.NOT_FOUND,
                message=error_msg
            )
            
        try:
            # Extract template data
            template_dict = self._to_dict(template)
            
            # Create base rule data from template
            rule_data = {
                "name": customization.get("name", template_dict.get("name", f"Rule from template {template_id}")),
                "description": customization.get("description", template_dict.get("description")),
                "patient_id": patient_id,
                "is_active": customization.get("is_active", True),
                "template_id": template_id,
                "provider_id": customization.get("provider_id"),
                "priority": customization.get("priority", template_dict.get("default_priority", "medium")),
                "logical_operator": customization.get("logical_operator", template_dict.get("logical_operator", "and")),
            }
            
            # Process conditions with customizations
            conditions = []
            template_conditions = template_dict.get("conditions", [])
            
            # Get threshold customizations
            threshold_customizations = {}
            if "threshold_value" in customization:
                threshold_customizations = customization["threshold_value"]
                
            # Create conditions from template with any customizations applied
            for template_condition in template_conditions:
                metric_name = template_condition.get("metric_name", "unknown").lower()
                
                # Create base condition from template
                condition = {
                    "metric_name": metric_name,
                    "comparator_operator": template_condition.get("comparator_operator", "greater_than"),
                    "threshold_value": template_condition.get("threshold_value", 0.0),
                    "description": template_condition.get("description"),
                    "duration_minutes": template_condition.get("duration_minutes"),
                }
                
                # Apply customization for the specific metric if available
                if metric_name in threshold_customizations:
                    condition["threshold_value"] = threshold_customizations[metric_name]
                    
                conditions.append(condition)
                
            # Add conditions to rule data
            rule_data["conditions"] = conditions
            
            # Create new rule entity
            alert_rule = await self._create_rule_from_dict(rule_data)
            
            # Return the created rule data
            return self._to_dict(alert_rule)
            
        except Exception as e:
            error_msg = f"Failed to apply template: {str(e)}"
            logger.error(error_msg)
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=error_msg
            )
            
    async def _create_rule_from_dict(self, rule_data: Dict[str, Any]) -> BiometricAlertRule:
        """
        Create a rule entity from a dictionary and save it.
        
        Args:
            rule_data: Dictionary containing rule data
            
        Returns:
            Created rule entity
            
        Raises:
            ApplicationError: If creation fails
        """
        try:
            # Map priority string to enum
            priority_str = rule_data.get("priority", "medium").upper()
            try:
                priority = getattr(AlertPriority, priority_str)
            except (AttributeError, ValueError):
                priority = AlertPriority.MEDIUM
                
            # Map logical operator string to enum
            logical_op_str = rule_data.get("logical_operator", "and").upper()
            try:
                logical_operator = getattr(RuleLogicalOperator, logical_op_str)
            except (AttributeError, ValueError):
                logical_operator = RuleLogicalOperator.AND
                
            # Create conditions
            conditions = []
            for condition_data in rule_data.get("conditions", []):
                # Map metric name to enum
                metric_name = condition_data.get("metric_name", "").upper()
                try:
                    metric_type = getattr(BiometricMetricType, metric_name)
                except (AttributeError, ValueError):
                    # Skip invalid metrics
                    logger.warning(f"Invalid metric name: {metric_name}")
                    continue
                    
                # Map operator name to enum
                operator_name = condition_data.get("comparator_operator", "greater_than").lower()
                operator_map = {
                    "greater_than": ComparatorOperator.GREATER_THAN,
                    "less_than": ComparatorOperator.LESS_THAN,
                    "equal_to": ComparatorOperator.EQUAL_TO,
                    "greater_than_or_equal": ComparatorOperator.GREATER_THAN_OR_EQUAL,
                    "less_than_or_equal": ComparatorOperator.LESS_THAN_OR_EQUAL,
                    "not_equal": ComparatorOperator.NOT_EQUAL,
                    ">": ComparatorOperator.GREATER_THAN,
                    "<": ComparatorOperator.LESS_THAN,
                    "=": ComparatorOperator.EQUAL_TO,
                    ">=": ComparatorOperator.GREATER_THAN_OR_EQUAL,
                    "<=": ComparatorOperator.LESS_THAN_OR_EQUAL,
                    "!=": ComparatorOperator.NOT_EQUAL,
                }
                operator = operator_map.get(operator_name, ComparatorOperator.GREATER_THAN)
                
                # Create condition
                condition = RuleCondition(
                    metric_type=metric_type,
                    operator=operator,
                    threshold_value=float(condition_data.get("threshold_value", 0)),
                    description=condition_data.get("description")
                )
                conditions.append(condition)
                
            # Create rule entity
            rule = BiometricAlertRule(
                name=rule_data.get("name", "Rule from template"),
                description=rule_data.get("description"),
                patient_id=rule_data["patient_id"],  # Required
                conditions=conditions,
                logical_operator=logical_operator,
                priority=priority,
                is_active=rule_data.get("is_active", True),
                provider_id=rule_data.get("provider_id"),
                template_id=rule_data.get("template_id")
            )
            
            # Save rule to repository
            return await self.rule_repository.save(rule)
            
        except Exception as e:
            error_msg = f"Failed to create rule from dictionary: {str(e)}"
            logger.error(error_msg)
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=error_msg
            )
    
    def _to_dict(self, entity: Any) -> Dict[str, Any]:
        """
        Convert an entity to a dictionary.
        
        Args:
            entity: Entity to convert
            
        Returns:
            Dictionary representation of the entity
        """
        if hasattr(entity, "model_dump"):
            # For pydantic v2 models (preferred)
            return entity.model_dump()
        elif hasattr(entity, "dict"):
            # For older pydantic v1 models (backward compatibility)
            return entity.dict()
        elif hasattr(entity, "__dict__"):
            # For regular classes
            return {k: v for k, v in entity.__dict__.items() if not k.startswith("_")}
        else:
            # For dictionary-like objects
            return dict(entity)
