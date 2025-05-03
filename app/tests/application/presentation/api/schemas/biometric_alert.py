# -*- coding: utf-8 -*-
"""
Pydantic schemas for biometric alert API endpoints.

These schemas define the data structures for request and response payloads
in the biometric alert API endpoints, including alert rules and templates.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Literal
from uuid import UUID

# Import ConfigDict for V2 style config
from pydantic import BaseModel, Field, ConfigDict, model_validator

# Import domain enums to ensure type consistency
from app.domain.entities.biometric_alert import AlertStatusEnum as DomainAlertStatusEnum
from app.domain.entities.biometric_alert_rule import AlertPriority as DomainAlertPriority


class MetricTypeEnum(str, Enum):
    """Types of biometric metrics that can be monitored."""
    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE = "blood_pressure"
    BLOOD_GLUCOSE = "blood_glucose"
    OXYGEN_SATURATION = "oxygen_saturation"
    TEMPERATURE = "temperature"
    RESPIRATORY_RATE = "respiratory_rate"
    SLEEP = "sleep"
    WEIGHT = "weight"
    ACTIVITY = "activity"
    STEPS = "steps"


class ComparatorOperatorEnum(str, Enum):
    """Comparison operators for rule conditions."""
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    EQUAL = "eq"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN_OR_EQUAL = "lte"
    NOT_EQUAL = "ne"
    
    # Legacy aliases for tests
    GT = ">"
    LT = "<"
    EQ = "=="
    GTE = ">="
    LTE = "<="
    NE = "!="


class LogicalOperatorEnum(str, Enum):
    """Logical operators for combining rule conditions."""
    AND = "and"
    OR = "or"


class AlertPriorityEnum(str, Enum):
    """Priority levels for biometric alerts."""
    URGENT = "urgent"
    WARNING = "warning"
    INFORMATIONAL = "informational"
    # Aliases for backward compatibility with tests
    HIGH = "urgent"
    MEDIUM = "warning"
    LOW = "informational"


class DataPointSchema(BaseModel):
    """Schema for a biometric data point that triggered an alert."""
    data_id: UUID | str = Field(..., description="Unique identifier for the data point")
    data_type: str = Field(..., description="Type of biometric data (e.g., heart_rate, blood_pressure)")
    value: float = Field(..., description="Value of the biometric measurement")
    timestamp: datetime = Field(..., description="When the measurement was taken")
    source: str = Field(..., description="Source of the measurement (e.g., apple_watch, fitbit)")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional context about the measurement")
    confidence: Optional[float] = Field(default=None, description="Confidence score for the data point (0.0 to 1.0)")
    
    model_config = ConfigDict(from_attributes=True)


class BiometricAlertCreateSchema(BaseModel):
    """Schema for creating a new biometric alert."""
    patient_id: UUID = Field(..., description="ID of the patient this alert is for")
    alert_type: str = Field(..., description="Type of alert (e.g., elevated_heart_rate, sleep_disruption)")
    description: str = Field(..., description="Human-readable description of the alert")
    priority: AlertPriorityEnum = Field(..., description="Urgency level of the alert")
    data_points: List[Dict[str, Any]] = Field(..., description="Biometric data points that triggered the alert")
    rule_id: UUID = Field(..., description="ID of the clinical rule that generated this alert")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional contextual information")


class BiometricAlertResponseSchema(BaseModel):
    """Schema for biometric alert responses."""
    alert_id: UUID = Field(..., description="Unique identifier for this alert")
    patient_id: UUID = Field(..., description="ID of the patient this alert is for")
    rule_name: str = Field(..., description="Name of the rule that triggered the alert")
    message: str = Field(..., description="Human-readable message describing the alert")
    priority: DomainAlertPriority = Field(..., description="Urgency level of the alert")
    status: DomainAlertStatusEnum = Field(..., description="Current status of the alert")
    created_at: datetime = Field(..., description="When the alert was triggered/created")
    updated_at: datetime = Field(..., description="When the alert was last updated")
    data_point: DataPointSchema = Field(..., description="The biometric data point that triggered the alert")
    rule_id: UUID = Field(..., description="ID of the clinical rule that generated this alert")
    
    # State flags matching the entity
    acknowledged: bool = Field(..., description="Whether the alert has been acknowledged")
    resolved: bool = Field(..., description="Whether the alert has been resolved")
    
    # Acknowledgment and resolution fields
    acknowledged_by: Optional[UUID] = Field(default=None, description="ID of the provider who acknowledged the alert")
    acknowledged_at: Optional[datetime] = Field(default=None, description="When the alert was acknowledged")
    acknowledged_notes: Optional[str] = Field(default=None, description="Notes entered during acknowledgment")
    resolved_by: Optional[UUID] = Field(default=None, description="ID of the provider who resolved the alert")
    resolved_at: Optional[datetime] = Field(default=None, description="When the alert was resolved")
    resolved_notes: Optional[str] = Field(default=None, description="Notes on how the alert was resolved")
    
    # Additional data
    context: Optional[Dict[str, Any]] = Field(default=None, description="Additional contextual information")
    
    # V2 Config
    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdateSchema(BaseModel):
    """Schema for updating the status of a biometric alert."""
    status: DomainAlertStatusEnum = Field(..., description="New status for the alert")
    notes: Optional[str] = Field(default=None, description="Optional notes about the status update")


class AlertListResponseSchema(BaseModel):
    """Schema for paginated list of biometric alerts."""
    items: List[BiometricAlertResponseSchema] = Field(..., description="List of biometric alerts")
    total: int = Field(..., description="Total number of alerts matching the criteria")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    
    # V2 Config
    model_config = ConfigDict(from_attributes=True)


# Alert Rule Schemas
class RuleConditionSchema(BaseModel):
    """Schema for a condition in an alert rule."""
    metric: str = Field(..., description="Name of the metric to check (e.g., heart_rate)")
    operator: str = Field(..., description="Comparison operator (e.g., gt, lt, eq)")
    threshold: float = Field(..., description="Threshold value for the condition")
    duration_minutes: Optional[int] = Field(default=0, description="Duration in minutes for condition to persist")
    
    model_config = ConfigDict(from_attributes=True)


class RuleConditionResponseSchema(BaseModel):
    """Schema for a condition in an alert rule response."""
    metric: str = Field(..., description="Name of the metric that's being monitored")
    operator: str = Field(..., description="Comparison operator used")
    threshold: float = Field(..., description="Threshold value for the condition")
    duration_minutes: Optional[int] = Field(default=0, description="Duration in minutes")
    
    model_config = ConfigDict(from_attributes=True)


class AlertRuleCustomizationSchema(BaseModel):
    """Schema for customizing a rule template."""
    name: Optional[str] = Field(default=None, description="Custom name for the rule")
    description: Optional[str] = Field(default=None, description="Custom description for the rule")
    threshold_modifications: Optional[Dict[str, float]] = Field(default=None, description="Modifications to threshold values")
    priority: Optional[AlertPriorityEnum] = Field(default=None, description="Override for the rule priority")
    
    model_config = ConfigDict(from_attributes=True)


class AlertRuleCreateSchema(BaseModel):
    """Schema for creating a new alert rule."""
    name: Optional[str] = Field(default=None, description="Name of the rule")
    description: Optional[str] = Field(default=None, description="Description of the rule")
    patient_id: Optional[UUID] = Field(default=None, description="ID of the patient this rule is for (None for global rules)")
    template_id: Optional[UUID] = Field(default=None, description="ID of the template to create from")
    customization: Optional[AlertRuleCustomizationSchema] = Field(default=None, description="Customization for the template")
    conditions: Optional[List[RuleConditionSchema]] = Field(default=None, description="Conditions for the rule")
    logical_operator: Optional[LogicalOperatorEnum] = Field(default="AND", description="Logical operator to combine conditions (AND/OR)")
    priority: Optional[AlertPriorityEnum] = Field(default=AlertPriorityEnum.WARNING, description="Priority level for alerts generated by this rule")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata for the rule")
    
    model_config = ConfigDict(from_attributes=True)
    
    @model_validator(mode='before')
    def validate_creation_method(cls, data):
        """Validate that either template_id or (name, description, conditions) are provided."""
        if isinstance(data, dict):
            if data.get("template_id") is None:
                if not (data.get("name") and data.get("conditions")):
                    raise ValueError("Either template_id or (name and conditions) must be provided")
        return data


class AlertRuleUpdateSchema(BaseModel):
    """Schema for updating an existing alert rule."""
    name: Optional[str] = Field(default=None, description="New name for the rule")
    description: Optional[str] = Field(default=None, description="New description for the rule")
    conditions: Optional[List[RuleConditionSchema]] = Field(default=None, description="New conditions for the rule")
    logical_operator: Optional[LogicalOperatorEnum] = Field(default=None, description="New logical operator to combine conditions")
    priority: Optional[AlertPriorityEnum] = Field(default=None, description="New priority level for alerts generated by this rule")
    is_active: Optional[bool] = Field(default=None, description="Whether the rule is active")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="New additional metadata for the rule")
    
    model_config = ConfigDict(from_attributes=True)


class AlertRuleResponseSchema(BaseModel):
    """Schema for alert rule responses."""
    rule_id: UUID = Field(..., description="Unique identifier for this rule")
    name: str = Field(..., description="Name of the rule")
    description: str = Field(..., description="Description of the rule")
    patient_id: Optional[UUID] = Field(default=None, description="ID of the patient this rule is for (None for global rules)")
    conditions: List[RuleConditionResponseSchema] = Field(..., description="Conditions for the rule")
    logical_operator: str = Field(..., description="Logical operator to combine conditions (AND/OR)")
    priority: str = Field(..., description="Priority level for alerts generated by this rule")
    is_active: bool = Field(..., description="Whether the rule is active")
    created_at: datetime = Field(..., description="When the rule was created")
    updated_at: Optional[datetime] = Field(default=None, description="When the rule was last updated")
    provider_id: Optional[UUID] = Field(default=None, description="ID of the provider who created or owns this rule")
    metadata: Optional[Dict[str, Any]] = Field(default={}, description="Additional metadata for the rule")
    
    model_config = ConfigDict(from_attributes=True)


class AlertRuleListResponseSchema(BaseModel):
    """Schema for paginated list of alert rules."""
    rules: List[AlertRuleResponseSchema] = Field(..., description="List of alert rules")
    total: int = Field(..., description="Total number of rules matching the criteria")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    
    model_config = ConfigDict(from_attributes=True)


class AlertRuleTemplateResponseSchema(BaseModel):
    """Schema for alert rule templates."""
    template_id: UUID = Field(..., description="Unique identifier for this template")
    name: str = Field(..., description="Name of the template")
    description: str = Field(..., description="Description of the template")
    category: str = Field(..., description="Category of the template (e.g., cardiac, sleep)")
    conditions: List[RuleConditionSchema] = Field(..., description="Default conditions for the template")
    logical_operator: str = Field(..., description="Default logical operator to combine conditions (AND/OR)")
    default_priority: AlertPriorityEnum = Field(..., description="Default priority level for alerts generated by this template")
    customizable_fields: List[str] = Field(..., description="Fields that can be customized when creating a rule from this template")
    
    model_config = ConfigDict(from_attributes=True)


class PatientAlertSummarySchema(BaseModel):
    """Schema for a summary of patient alerts."""
    patient_id: UUID = Field(..., description="ID of the patient")
    total_alerts: int = Field(..., description="Total number of alerts for this patient")
    new_alerts: int = Field(..., description="Number of new (unacknowledged) alerts")
    urgent_alerts: int = Field(..., description="Number of urgent priority alerts")
    warning_alerts: int = Field(..., description="Number of warning priority alerts")
    informational_alerts: int = Field(..., description="Number of informational priority alerts")
    last_alert_timestamp: Optional[datetime] = Field(default=None, description="Timestamp of the most recent alert")
    
    model_config = ConfigDict(from_attributes=True)


class AlertResponseSchema(BaseModel):
    """Schema for biometric alert responses."""
    alert_id: UUID = Field(..., description="Unique identifier for this alert")
    patient_id: UUID = Field(..., description="ID of the patient this alert is for")
    alert_type: str = Field(..., description="Type of alert (e.g., elevated_heart_rate, sleep_disruption)")
    description: str = Field(..., description="Human-readable description of the alert")
    priority: str = Field(..., description="Urgency level of the alert")
    status: str = Field(..., description="Current status of the alert")
    created_at: datetime = Field(..., description="When the alert was created")
    updated_at: datetime = Field(..., description="When the alert was last updated")
    data_points: List[Dict[str, Any]] = Field(..., description="Biometric data points that triggered the alert")
    rule_id: UUID = Field(..., description="ID of the clinical rule that generated this alert")
    
    # Acknowledgment and resolution fields
    acknowledged_by: Optional[UUID] = Field(default=None, description="ID of the provider who acknowledged the alert")
    acknowledged_at: Optional[datetime] = Field(default=None, description="When the alert was acknowledged")
    resolved_by: Optional[UUID] = Field(default=None, description="ID of the provider who resolved the alert")
    resolved_at: Optional[datetime] = Field(default=None, description="When the alert was resolved")
    resolution_notes: Optional[str] = Field(default=None, description="Notes on how the alert was resolved")
    
    # Additional data
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional contextual information")
    
    # V2 Config
    model_config = ConfigDict(from_attributes=True)


class AlertRuleCreateFromTemplateSchema(BaseModel):
    """Schema for creating an alert rule from a template."""
    name: str = Field(..., description="Name of the rule")
    description: str = Field(..., description="Description of the rule")
    patient_id: UUID = Field(..., description="ID of the patient this rule is for")
    template_id: str = Field(..., description="ID of the template to create from")
    parameters: Dict[str, Any] = Field(..., description="Parameters for the template")
    priority: Optional[AlertPriorityEnum] = Field(default=AlertPriorityEnum.WARNING, description="Priority level for alerts")
    
    model_config = ConfigDict(from_attributes=True)


class AlertRuleCreateFromConditionSchema(BaseModel):
    """Schema for creating an alert rule from a condition."""
    name: str = Field(..., description="Name of the rule")
    description: str = Field(..., description="Description of the rule")
    patient_id: UUID = Field(..., description="ID of the patient this rule is for")
    condition: Dict[str, Any] = Field(..., description="Condition for the rule")
    priority: Optional[AlertPriorityEnum] = Field(default=AlertPriorityEnum.WARNING, description="Priority level for alerts")
    
    model_config = ConfigDict(from_attributes=True)