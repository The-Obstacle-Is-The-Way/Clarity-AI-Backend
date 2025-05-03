"""
Alert Schemas Module.

This module defines Pydantic models for alert data validation,
serialization, and documentation in the presentation layer, ensuring
strict validation of all input and output data for HIPAA compliance.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, validator

from app.core.domain.entities.alert import AlertType, AlertPriority, AlertStatus
from app.presentation.api.schemas.base import BaseModelConfig


class AlertBase(BaseModelConfig):
    """Base schema for alert data with common fields."""
    alert_type: AlertType
    timestamp: datetime
    priority: AlertPriority
    message: str = Field(..., min_length=1, max_length=500)
    data: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @validator("timestamp")
    def validate_timestamp(cls, v):
        """Ensure timestamp is not in the future."""
        if v > datetime.now():
            raise ValueError("Timestamp cannot be in the future")
        return v


class AlertCreateRequest(AlertBase):
    """Request schema for creating a new alert."""
    patient_id: Optional[str] = None  # For provider-created alerts


class AlertUpdateRequest(BaseModelConfig):
    """Request schema for updating an existing alert."""
    status: Optional[AlertStatus] = None
    priority: Optional[AlertPriority] = None
    message: Optional[str] = Field(None, min_length=1, max_length=500)
    data: Optional[Dict[str, Any]] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = Field(None, min_length=1, max_length=1000)

    @validator("resolved_at")
    def validate_resolved_at(cls, v, values):
        """Ensure resolved_at is only set when status is RESOLVED."""
        if v and values.get("status") != AlertStatus.RESOLVED:
            raise ValueError("Resolved timestamp can only be set when status is RESOLVED")
        return v


class AlertResponse(AlertBase):
    """Response schema for alert data."""
    id: UUID
    status: AlertStatus
    user_id: str  # The ID of the patient this alert belongs to
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None


class AlertsFilterParams(BaseModelConfig):
    """Filter parameters for querying alerts."""
    status: Optional[AlertStatus] = None
    priority: Optional[AlertPriority] = None
    alert_type: Optional[AlertType] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
