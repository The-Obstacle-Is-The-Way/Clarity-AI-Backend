"""
Pydantic schemas for biometric data API endpoints.

This module defines the request and response schemas for the biometric data
API endpoints, ensuring proper validation and serialization of data.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

# Import ConfigDict for V2 style config
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer

from app.domain.utils.datetime_utils import now_utc


class BiometricDataPointCreate(BaseModel):
    """Schema for creating a new biometric data point."""

    data_type: str = Field(
        ...,
        description="Type of biometric data (e.g., 'heart_rate', 'blood_pressure')",
        examples=["heart_rate", "blood_pressure", "sleep_quality"],
    )
    value: float | int | str | dict[str, Any] = Field(
        ...,
        description="The measured value (can be numeric, string, or structured data)",
        examples=[75, "120/80", {"deep_sleep": 3.5, "rem_sleep": 2.1}],
    )
    source: str = Field(
        ...,
        description="Device or system that provided the measurement",
        examples=["smartwatch", "blood_pressure_monitor", "sleep_tracker"],
    )
    timestamp: datetime | None = Field(
        default_factory=now_utc,
        description="When the measurement was taken (defaults to current time)",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Additional contextual information about the measurement",
        examples=[{"activity": "resting"}, {"location": "home"}],
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence level in the measurement (0.0-1.0)",
    )

    @field_validator("data_type")
    def validate_data_type(cls, v):
        """Validate that data_type is not empty."""
        if not v or not v.strip():
            raise ValueError("Biometric data type cannot be empty")
        return v


class BiometricDataPointBatchCreate(BaseModel):
    """Schema for creating multiple biometric data points in a batch."""

    data_points: list[BiometricDataPointCreate] = Field(
        ..., min_length=1, description="List of biometric data points to create"
    )


class BiometricDataPointResponse(BaseModel):
    """Schema for biometric data point response."""

    data_id: UUID = Field(..., description="Unique identifier for this data point")
    data_type: str = Field(..., description="Type of biometric data")
    value: float | int | str | dict[str, Any] = Field(
        ..., description="The measured value"
    )
    timestamp: datetime = Field(..., description="When the measurement was taken")
    source: str = Field(
        ..., description="Device or system that provided the measurement"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional contextual information about the measurement",
    )
    confidence: float = Field(
        ..., description="Confidence level in the measurement (0.0-1.0)"
    )

    # V2 Config
    model_config = ConfigDict()

    @model_serializer
    def serialize_model(self) -> dict:
        return {
            "data_id": str(self.data_id),
            "data_type": self.data_type,
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "metadata": self.metadata,
            "confidence": self.confidence,
        }


class BiometricDataPointListResponse(BaseModel):
    """Schema for a list of biometric data points."""

    data_points: list[BiometricDataPointResponse] = Field(
        ..., description="List of biometric data points"
    )
    count: int = Field(..., description="Total number of data points in the response")


class BiometricTwinResponse(BaseModel):
    """Schema for biometric twin response."""

    twin_id: UUID = Field(..., description="Unique identifier for this biometric twin")
    patient_id: UUID = Field(..., description="ID of the patient this twin represents")
    created_at: datetime = Field(..., description="When this twin was first created")
    updated_at: datetime = Field(..., description="When this twin was last updated")
    baseline_established: bool = Field(
        ..., description="Whether baseline measurements have been established"
    )
    connected_devices: list[str] = Field(
        default_factory=list,
        description="List of devices currently connected to this twin",
    )
    data_points_count: int = Field(
        ..., description="Number of data points associated with this twin"
    )

    # V2 Config
    model_config = ConfigDict()

    @model_serializer
    def serialize_model(self) -> dict:
        return {
            "twin_id": str(self.twin_id),
            "patient_id": str(self.patient_id),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "baseline_established": self.baseline_established,
            "connected_devices": self.connected_devices,
            "data_points_count": self.data_points_count,
        }


class DeviceConnectionRequest(BaseModel):
    """Schema for connecting a device to a biometric twin."""

    device_id: str = Field(
        ...,
        description="Unique identifier for the device",
        examples=["smartwatch-123", "glucose-monitor-456"],
    )
    device_type: str = Field(
        ...,
        description="Type of device",
        examples=["smartwatch", "glucose_monitor", "blood_pressure_monitor"],
    )
    connection_metadata: dict[str, Any] | None = Field(
        default=None,
        description="Additional information about the connection",
        examples=[{"model": "Apple Watch Series 7", "os_version": "8.5"}],
    )


class DeviceDisconnectionRequest(BaseModel):
    """Schema for disconnecting a device from a biometric twin."""

    device_id: str = Field(
        ...,
        description="Unique identifier for the device",
        examples=["smartwatch-123", "glucose-monitor-456"],
    )
    reason: str | None = Field(
        default="user_initiated",
        description="Reason for disconnection",
        examples=["user_initiated", "battery_low", "connection_lost"],
    )


class TrendAnalysisResponse(BaseModel):
    """Schema for trend analysis response."""

    status: str = Field(
        ...,
        description="Status of the analysis",
        examples=["success", "insufficient_data", "invalid_data"],
    )
    data_type: str = Field(..., description="Type of biometric data analyzed")
    period: str = Field(
        ..., description="Time period of the analysis", examples=["7 days", "30 days"]
    )
    data_points_count: int = Field(
        ..., description="Number of data points included in the analysis"
    )
    average: float | None = Field(
        default=None, description="Average value over the period"
    )
    minimum: float | None = Field(
        default=None, description="Minimum value over the period"
    )
    maximum: float | None = Field(
        default=None, description="Maximum value over the period"
    )
    trend: str | None = Field(
        default=None,
        description="Detected trend direction",
        examples=["increasing", "decreasing", "stable", "fluctuating"],
    )
    last_value: float | None = Field(default=None, description="Most recent value")
    last_updated: str | None = Field(
        default=None, description="Timestamp of the most recent data point"
    )
    message: str | None = Field(
        default=None, description="Additional information or explanation"
    )


class CorrelationAnalysisRequest(BaseModel):
    """Schema for correlation analysis request."""

    primary_data_type: str = Field(
        ...,
        description="Primary type of biometric data",
        examples=["heart_rate", "stress_level"],
    )
    secondary_data_types: list[str] = Field(
        ...,
        min_length=1,
        description="Other types to correlate with the primary type",
        examples=[["sleep_quality", "activity_level", "stress_level"]],
    )
    window_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Number of days to include in the analysis",
    )


class CorrelationAnalysisResponse(BaseModel):
    """Schema for correlation analysis response."""

    correlations: dict[str, float] = Field(
        ..., description="Dictionary mapping data types to correlation coefficients"
    )
    primary_data_type: str = Field(
        ..., description="Primary type of biometric data used in the analysis"
    )
    window_days: int = Field(..., description="Number of days included in the analysis")
    data_points_count: dict[str, int] = Field(
        ...,
        description="Dictionary mapping data types to the number of data points used",
    )
