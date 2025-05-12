"""
Mapper functions for translating between BiometricRule domain entities and SQLAlchemy models.

This module provides functions to convert between domain entities and database models
for biometric rules, maintaining a clean separation between the domain and infrastructure layers.
"""

from datetime import datetime
from uuid import uuid4

from app.domain.entities.biometric_rule import (
    AlertPriority,
    BiometricRule,
    RuleCondition,
    RuleOperator,
)
from app.infrastructure.persistence.sqlalchemy.models.biometric_rule import BiometricRuleModel


def map_rule_entity_to_model(rule: BiometricRule) -> BiometricRuleModel:
    """
    Map a BiometricRule domain entity to a BiometricRuleModel database model.
    
    Args:
        rule: The domain entity to map
        
    Returns:
        The corresponding database model
    """
    # Create new UUID if none exists
    rule_id = rule.id if rule.id else uuid4()
    
    # Convert conditions to JSON-compatible format
    conditions_json = []
    for condition in rule.conditions:
        condition_dict = {
            "metric_name": condition.metric_name,
            "operator": condition.operator.value,
            "threshold_value": condition.threshold_value,
            "data_type": condition.data_type
        }
        conditions_json.append(condition_dict)
    
    # Set updated_at to current time if updating
    updated_at = datetime.now(datetime.UTC) if rule.id else None
    
    # Convert alert_priority to string value
    priority_str = rule.alert_priority.value if isinstance(rule.alert_priority, AlertPriority) else rule.alert_priority
    
    # Create and return model
    return BiometricRuleModel(
        id=rule_id,
        name=rule.name,
        description=rule.description,
        conditions=conditions_json,
        logical_operator=rule.logical_operator,
        alert_priority=priority_str,
        is_active=rule.is_active,
        patient_id=rule.patient_id,
        provider_id=rule.provider_id,
        created_at=rule.created_at if rule.created_at else datetime.now(datetime.UTC),
        updated_at=updated_at,
        rule_metadata=rule.metadata
    )


def map_rule_model_to_entity(model: BiometricRuleModel) -> BiometricRule:
    """
    Map a BiometricRuleModel database model to a BiometricRule domain entity.
    
    Args:
        model: The database model to map
        
    Returns:
        The corresponding domain entity
    """
    # Convert JSON conditions to domain RuleCondition objects
    conditions = []
    for condition_dict in model.conditions:
        # Convert operator string to enum
        operator_str = condition_dict.get("operator")
        operator = RuleOperator(operator_str) if operator_str else RuleOperator.GREATER_THAN
        
        # Create RuleCondition object
        condition = RuleCondition(
            metric_name=condition_dict.get("metric_name"),
            operator=operator,
            threshold_value=condition_dict.get("threshold_value"),
            data_type=condition_dict.get("data_type")
        )
        conditions.append(condition)
    
    # Convert alert_priority string to enum
    try:
        alert_priority = AlertPriority(model.alert_priority)
    except (ValueError, TypeError):
        # Default to WARNING if invalid or None
        alert_priority = AlertPriority.WARNING
    
    # Create and return entity
    return BiometricRule(
        id=model.id,
        name=model.name,
        description=model.description,
        conditions=conditions,
        logical_operator=model.logical_operator,
        alert_priority=alert_priority,
        is_active=model.is_active,
        patient_id=model.patient_id,
        provider_id=model.provider_id,
        created_at=model.created_at,
        updated_at=model.updated_at,
        metadata=model.rule_metadata
    )
