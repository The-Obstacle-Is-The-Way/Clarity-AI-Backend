"""
Alert Schemas Module.

This module defines Pydantic models for alert data validation,
serialization, and documentation in the presentation layer, ensuring
strict validation of all input and output data for HIPAA compliance.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field, validator

from app.core.domain.entities.alert import AlertPriority, AlertStatus, AlertType
from app.presentation.api.schemas.base import BaseModelConfig


class AlertBase(BaseModelConfig):
    """Base schema for alert data with common fields."""
    alert_type: AlertType
    timestamp: datetime
    priority: AlertPriority
    message: str = Field(..., min_length=1, max_length=500)
    data: dict[str, Any] | None = Field(default_factory=dict)

    @validator("timestamp")
    def validate_timestamp(cls, v):
        """Ensure timestamp is not in the future."""
        if v > datetime.now():
            raise ValueError("Timestamp cannot be in the future")
        return v


class AlertCreateRequest(AlertBase):
    """Request schema for creating a new alert."""
    patient_id: str | None = None  # For provider-created alerts


class AlertUpdateRequest(BaseModelConfig):
    """Request schema for updating an existing alert."""
    status: AlertStatus | None = None
    priority: AlertPriority | None = None
    message: str | None = Field(None, min_length=1, max_length=500)
    data: dict[str, Any] | None = None
    resolved_at: datetime | None = None
    resolution_notes: str | None = Field(None, min_length=1, max_length=1000)

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
    resolved_at: datetime | None = None
    resolution_notes: str | None = None


class AlertsFilterParams(BaseModelConfig):
    """Filter parameters for querying alerts."""
    status: AlertStatus | None = None
    priority: AlertPriority | None = None
    alert_type: AlertType | None = None
    start_date: str | None = None
    end_date: str | None = None
