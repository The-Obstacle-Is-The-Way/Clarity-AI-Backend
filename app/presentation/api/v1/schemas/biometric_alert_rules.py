"""
API schemas for biometric alert rules endpoints.

This module contains Pydantic models for request and response serialization
for biometric alert rules API endpoints, following clean architecture principles.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any
from uuid import UUID

from pydantic import BaseModel, Field, validator
from pydantic import ConfigDict

from app.domain.entities.biometric_alert_rule import (
    AlertPriority,
    BiometricAlertRule,
    BiometricMetricType,
    ComparatorOperator,
    RuleCondition,
    RuleLogicalOperator,
)


# ======== Enums for API ========

class ApiAlertPriority(str, Enum):
    """Alert priority levels exposed in the API."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ApiComparatorOperator(str, Enum):
    """Comparator operators exposed in the API."""
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    EQUAL_TO = "equal_to"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    NOT_EQUAL = "not_equal"


class ApiLogicalOperator(str, Enum):
    """Logical operators exposed in the API."""
    AND = "and"
    OR = "or"


class ApiMetricType(str, Enum):
    """Biometric metric types exposed in the API."""
    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE = "blood_pressure"
    BLOOD_OXYGEN = "blood_oxygen"
    TEMPERATURE = "temperature"
    RESPIRATORY_RATE = "respiratory_rate"
    GLUCOSE = "glucose"
    WEIGHT = "weight"
    STEPS = "steps"
    SLEEP = "sleep"
    ACTIVITY = "activity"


# ======== Base Models ========

class RuleConditionBase(BaseModel):
    """Base model for rule conditions."""
    metric_name: str = Field(..., description="Biometric metric name")
    comparator_operator: ApiComparatorOperator = Field(..., description="Comparison operator")
    threshold_value: float = Field(..., description="Threshold value for comparison")
    duration_minutes: Optional[int] = Field(None, description="Duration in minutes condition must persist")
    description: Optional[str] = Field(None, description="Optional description of condition")


class AlertRuleBase(BaseModel):
    """Base model for alert rules."""
    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None, description="Rule description")
    priority: ApiAlertPriority = Field(ApiAlertPriority.MEDIUM, description="Alert priority level")
    logical_operator: ApiLogicalOperator = Field(ApiLogicalOperator.AND, description="Logical operator for conditions")
    is_active: bool = Field(True, description="Whether rule is active")


# ======== Request Models ========

class AlertRuleCreate(AlertRuleBase):
    """Model for creating a new alert rule."""
    patient_id: UUID = Field(..., description="Patient this rule applies to")
    conditions: List[RuleConditionBase] = Field(..., description="Rule conditions", min_items=1)


class TemplateCustomization(BaseModel):
    """Model for template customization options."""
    priority: Optional[ApiAlertPriority] = Field(None, description="Override default priority")
    threshold_value: Optional[Dict[str, float]] = Field(None, description="Override thresholds by metric")
    is_active: Optional[bool] = Field(None, description="Override active status")


class RuleFromTemplateCreate(BaseModel):
    """Model for creating a rule from a template."""
    template_id: UUID = Field(..., description="Template to base the rule on")
    patient_id: UUID = Field(..., description="Patient this rule applies to")
    customization: TemplateCustomization = Field(..., description="Template customization")


class AlertRuleUpdate(BaseModel):
    """Model for updating an existing alert rule."""
    name: Optional[str] = Field(None, description="Rule name")
    description: Optional[str] = Field(None, description="Rule description")
    priority: Optional[ApiAlertPriority] = Field(None, description="Alert priority level")
    logical_operator: Optional[ApiLogicalOperator] = Field(None, description="Logical operator for conditions")
    is_active: Optional[bool] = Field(None, description="Whether rule is active")
    conditions: Optional[List[RuleConditionBase]] = Field(None, description="Rule conditions")


class AlertRuleWrapperRequest(BaseModel):
    """Wrapper model for rule data that matches the test payload format."""
    rule_data: AlertRuleCreate

    model_config = ConfigDict(
        extra="allow"
    )


# ======== Response Models ========

class RuleConditionResponse(RuleConditionBase):
    """Response model for rule conditions."""
    id: Optional[UUID] = Field(None, description="Condition ID if available")

    @classmethod
    def from_entity(cls, entity: RuleCondition) -> "RuleConditionResponse":
        """Convert domain entity to response schema."""
        # Map domain enums to API enums
        operator_map = {
            ComparatorOperator.GREATER_THAN: ApiComparatorOperator.GREATER_THAN,
            ComparatorOperator.LESS_THAN: ApiComparatorOperator.LESS_THAN,
            ComparatorOperator.EQUAL_TO: ApiComparatorOperator.EQUAL_TO,
            ComparatorOperator.GREATER_THAN_OR_EQUAL: ApiComparatorOperator.GREATER_THAN_OR_EQUAL,
            ComparatorOperator.LESS_THAN_OR_EQUAL: ApiComparatorOperator.LESS_THAN_OR_EQUAL,
            ComparatorOperator.NOT_EQUAL: ApiComparatorOperator.NOT_EQUAL,
        }
        
        return cls(
            metric_name=entity.metric_type.name.lower(),
            comparator_operator=operator_map.get(entity.operator, ApiComparatorOperator.GREATER_THAN),
            threshold_value=entity.threshold_value,
            duration_minutes=getattr(entity, "duration_minutes", None),
            description=entity.description,
            id=getattr(entity, "id", None)
        )


class AlertRuleResponse(AlertRuleBase):
    """Response model for alert rules."""
    id: UUID = Field(..., description="Rule ID")
    patient_id: UUID = Field(..., description="Patient this rule applies to")
    provider_id: Optional[UUID] = Field(None, description="Provider who created the rule")
    conditions: List[RuleConditionResponse] = Field(..., description="Rule conditions")
    template_id: Optional[UUID] = Field(None, description="Template this rule was based on")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

    @classmethod
    def from_entity(cls, entity: BiometricAlertRule) -> "AlertRuleResponse":
        """Convert domain entity to response schema."""
        # Map domain enums to API enums
        priority_map = {
            AlertPriority.CRITICAL: ApiAlertPriority.CRITICAL,
            AlertPriority.HIGH: ApiAlertPriority.HIGH,
            AlertPriority.MEDIUM: ApiAlertPriority.MEDIUM,
            AlertPriority.LOW: ApiAlertPriority.LOW,
            AlertPriority.INFO: ApiAlertPriority.INFO,
        }
        
        logical_op_map = {
            RuleLogicalOperator.AND: ApiLogicalOperator.AND,
            RuleLogicalOperator.OR: ApiLogicalOperator.OR,
        }
        
        return cls(
            id=entity.id,
            name=entity.name,
            description=entity.description,
            patient_id=entity.patient_id,
            provider_id=entity.provider_id,
            priority=priority_map.get(entity.priority, ApiAlertPriority.MEDIUM),
            logical_operator=logical_op_map.get(entity.logical_operator, ApiLogicalOperator.AND),
            is_active=entity.is_active,
            conditions=[RuleConditionResponse.from_entity(condition) for condition in entity.conditions],
            template_id=entity.template_id,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )


class AlertRuleList(BaseModel):
    """Response model for lists of alert rules."""
    items: List[AlertRuleResponse] = Field(..., description="List of alert rules")
    total: int = Field(..., description="Total count of matching rules")
    skip: int = Field(..., description="Number of rules skipped")
    limit: int = Field(..., description="Maximum number of rules returned")


class AlertRuleTemplateResponse(BaseModel):
    """Response model for rule templates."""
    template_id: str = Field(..., description="Unique template identifier")
    name: str = Field(..., description="Template name")
    description: str = Field(..., description="Template description")
    category: Optional[str] = Field(None, description="Template category")
    conditions: List[Dict[str, Any]] = Field(..., description="Template conditions")
    logical_operator: str = Field("and", description="Logical operator between conditions")
    default_priority: str = Field("medium", description="Default priority for alerts")
    customizable_fields: List[str] = Field([], description="Fields that can be customized")
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
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
            }
        } 