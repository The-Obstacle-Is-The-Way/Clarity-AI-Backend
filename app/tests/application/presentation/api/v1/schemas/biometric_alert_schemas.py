"""
Pydantic schemas for biometric alerts API endpoints.

This module defines the request and response schemas for the biometric alerts
API endpoints, ensuring proper validation and documentation of the API contract.
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


# Define AlertPriorityEnum based on domain AlertPriority
class AlertPriorityEnum(str, Enum):
    """Priority levels for biometric alerts (API Schema)."""
    URGENT = "urgent"
    WARNING = "warning"
    INFORMATIONAL = "informational"

class AlertRuleCreate(BaseModel):
    """Request model for creating an alert rule."""
    
    rule_id: str = Field(..., description="Unique identifier for the rule")
    name: str = Field(..., description="Name of the rule")
    description: str = Field(..., description="Description of the rule")
    priority: str = Field(..., description="Priority level of the rule (urgent, warning, informational)")
    condition: dict[str, Any] | None = Field(None, description="Condition that triggers the alert")
    template_id: str | None = Field(None, description="ID of the template to use for creating the rule")
    parameters: dict[str, Any] | None = Field(None, description="Parameters for the template")
    patient_id: UUID | None = Field(None, description="Optional ID of the patient this rule applies to")
    
    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        """Validate that the priority is one of the allowed values."""
        allowed_values = ["urgent", "warning", "informational"]
        if v.lower() not in allowed_values:
            raise ValueError(f"Priority must be one of {allowed_values}")
        return v
    
    @model_validator(mode='after')
    def validate_condition_or_template(self) -> 'AlertRuleCreate':
        """Validate that either condition or template_id is provided."""
        if self.condition is None and self.template_id is None:
            raise ValueError("Either condition or template_id must be provided")
        return self


class AlertRuleUpdate(BaseModel):
    """Request model for updating an alert rule."""
    
    name: str | None = Field(None, description="Name of the rule")
    description: str | None = Field(None, description="Description of the rule")
    priority: str | None = Field(None, description="Priority level of the rule (urgent, warning, informational)")
    condition: dict[str, Any] | None = Field(None, description="Condition that triggers the alert")
    is_active: bool | None = Field(None, description="Whether the rule is active")
    
    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str | None) -> str | None:
        """Validate that the priority is one of the allowed values."""
        if v is not None:
            allowed_values = ["urgent", "warning", "informational"]
            if v.lower() not in allowed_values:
                raise ValueError(f"Priority must be one of {allowed_values}")
        return v


class AlertRuleResponse(BaseModel):
    """Response model for an alert rule."""
    
    rule_id: str = Field(..., description="Unique identifier for the rule")
    name: str = Field(..., description="Name of the rule")
    description: str = Field(..., description="Description of the rule")
    priority: str = Field(..., description="Priority level of the rule (urgent, warning, informational)")
    condition: dict[str, Any] = Field(..., description="Condition that triggers the alert")
    created_by: UUID = Field(..., description="ID of the user who created the rule")
    patient_id: UUID | None = Field(None, description="Optional ID of the patient this rule applies to")
    created_at: datetime = Field(..., description="Timestamp of when the rule was created")
    updated_at: datetime = Field(..., description="Timestamp of when the rule was last updated")
    is_active: bool = Field(..., description="Whether the rule is active")


class AlertRuleListResponse(BaseModel):
    """Response model for a list of alert rules."""
    
    rules: list[AlertRuleResponse] = Field(..., description="List of alert rules")
    count: int = Field(..., description="Number of alert rules")


class AlertRuleTemplateResponse(BaseModel):
    """Response model for an alert rule template."""
    
    template_id: str = Field(..., description="Unique identifier for the template")
    name: str = Field(..., description="Name of the template")
    description: str = Field(..., description="Description of the template")
    required_parameters: list[str] = Field(..., description="List of required parameters for the template")
    condition_template: dict[str, Any] = Field(..., description="Template for the condition")


class AlertRuleTemplateListResponse(BaseModel):
    """Response model for a list of alert rule templates."""
    
    templates: list[AlertRuleTemplateResponse] = Field(..., description="List of alert rule templates")
    count: int = Field(..., description="Number of alert rule templates")


class BiometricDataPointResponse(BaseModel):
    """Response model for a biometric data point."""
    
    data_id: str = Field(..., description="Unique identifier for the data point")
    data_type: str = Field(..., description="Type of biometric data")
    value: float = Field(..., description="Value of the data point")
    timestamp: datetime = Field(..., description="Timestamp of when the data point was recorded")
    source: str = Field(..., description="Source of the data point")


class BiometricAlertResponse(BaseModel):
    """Response model for a biometric alert."""
    
    alert_id: str = Field(..., description="Unique identifier for the alert")
    patient_id: UUID = Field(..., description="ID of the patient")
    rule_id: str = Field(..., description="ID of the rule that triggered the alert")
    rule_name: str = Field(..., description="Name of the rule that triggered the alert")
    priority: str = Field(..., description="Priority level of the alert")
    message: str = Field(..., description="Alert message")
    created_at: datetime = Field(..., description="Timestamp of when the alert was created")
    acknowledged: bool = Field(..., description="Whether the alert has been acknowledged")
    acknowledged_at: datetime | None = Field(None, description="Timestamp of when the alert was acknowledged")
    acknowledged_by: UUID | None = Field(None, description="ID of the user who acknowledged the alert")
    data_point: dict[str, Any] = Field(..., description="Biometric data point that triggered the alert")


class BiometricAlertListResponse(BaseModel):
    """Response model for a list of biometric alerts."""
    
    alerts: list[BiometricAlertResponse] = Field(..., description="List of biometric alerts")
    count: int = Field(..., description="Number of biometric alerts")


class AlertAcknowledgementRequest(BaseModel):
    """Request model for acknowledging an alert."""
    
    notes: str | None = Field(None, description="Optional notes about the acknowledgement")

# Update forward references for all models in this file
AlertRuleCreate.update_forward_refs()
AlertRuleUpdate.update_forward_refs()
AlertRuleResponse.update_forward_refs()
AlertRuleListResponse.update_forward_refs()
AlertRuleTemplateResponse.update_forward_refs()
AlertRuleTemplateListResponse.update_forward_refs()
BiometricDataPointResponse.update_forward_refs()
BiometricAlertResponse.update_forward_refs()
BiometricAlertListResponse.update_forward_refs()
AlertAcknowledgementRequest.update_forward_refs()