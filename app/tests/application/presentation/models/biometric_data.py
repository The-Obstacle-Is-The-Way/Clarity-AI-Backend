"""
Biometric data API models.

This module defines Pydantic models for API requests and responses
related to biometric data in the digital twin system.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BiometricDataInput(BaseModel):
    """API model for incoming biometric data."""
    
    biometric_type: str = Field(
        ...,
        description="Type of biometric data (e.g., heart_rate, blood_pressure)",
        example="heart_rate"
    )
    
    value: float | int | dict[str, Any] = Field(
        ...,
        description="Measurement value, can be numeric or structured data",
        example=72.5
    )
    
    source: str = Field(
        ...,
        description="Source of the biometric data",
        example="wearable"
    )
    
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the data was recorded",
        example="2025-04-10T14:30:00"
    )
    
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional additional information about the reading",
        example={"device": "fitbit", "activity": "resting"}
    )
    
    @field_validator("biometric_type")
    def validate_biometric_type(cls, value: str) -> str:
        """Ensure biometric type is a valid string."""
        if not value or not isinstance(value, str):
            raise ValueError("Biometric type must be a non-empty string")
        return value.lower()
    
    @field_validator("source")
    def validate_source(cls, value: str) -> str:
        """Ensure source is a valid string."""
        if not value or not isinstance(value, str):
            raise ValueError("Source must be a non-empty string")
        return value.lower()
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "biometric_type": "heart_rate",
            "value": 72.5,
            "source": "wearable",
            "timestamp": "2025-04-10T14:30:00",
            "metadata": {
                "device": "fitbit",
                "activity": "resting"
            }
        }
    })


class BiometricDataOutput(BaseModel):
    """API model for biometric data output."""
    
    timestamp: datetime = Field(
        ...,
        description="When the data was recorded",
        example="2025-04-10T14:30:00"
    )
    
    value: float | int | dict[str, Any] = Field(
        ...,
        description="Measurement value, can be numeric or structured data",
        example=72.5
    )
    
    source: str = Field(
        ...,
        description="Source of the biometric data",
        example="wearable"
    )
    
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional additional information about the reading",
        example={"device": "fitbit", "activity": "resting"}
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "timestamp": "2025-04-10T14:30:00",
            "value": 72.5,
            "source": "wearable",
            "metadata": {
                "device": "fitbit",
                "activity": "resting"
            }
        }
    })


class BiometricHistoryParams(BaseModel):
    """API model for biometric history query parameters."""
    
    start_time: datetime | None = Field(
        default=None,
        description="Start time for filtering data",
        example="2025-04-01T00:00:00"
    )
    
    end_time: datetime | None = Field(
        default=None,
        description="End time for filtering data",
        example="2025-04-11T00:00:00"
    )
    
    @field_validator("end_time")
    def validate_time_range(cls, end_time: datetime | None, values: dict[str, Any]) -> datetime | None:
        """Ensure end_time is after start_time if both are provided."""
        start_time = values.get("start_time")
        if start_time and end_time and end_time < start_time:
            raise ValueError("End time must be after start time")
        return end_time
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "start_time": "2025-04-01T00:00:00",
            "end_time": "2025-04-11T00:00:00"
        }
    })


class PhysiologicalRangeModel(BaseModel):
    """API model for physiological range data."""
    
    min: float = Field(
        ...,
        description="Minimum value of the normal range",
        example=60.0
    )
    
    max: float = Field(
        ...,
        description="Maximum value of the normal range",
        example=100.0
    )
    
    critical_min: float = Field(
        ...,
        description="Minimum value before the measurement is considered critically low",
        example=40.0
    )
    
    critical_max: float = Field(
        ...,
        description="Maximum value before the measurement is considered critically high",
        example=140.0
    )
    
    @field_validator("max")
    def validate_max(cls, max_val: float, values: dict[str, Any]) -> float:
        """Ensure max is greater than min."""
        min_val = values.get("min")
        if min_val is not None and max_val <= min_val:
            raise ValueError("Max value must be greater than min value")
        return max_val
    
    @field_validator("critical_min")
    def validate_critical_min(cls, critical_min: float, values: dict[str, Any]) -> float:
        """Ensure critical_min is less than or equal to min."""
        min_val = values.get("min")
        if min_val is not None and critical_min > min_val:
            raise ValueError("Critical min value must be less than or equal to min value")
        return critical_min
    
    @field_validator("critical_max")
    def validate_critical_max(cls, critical_max: float, values: dict[str, Any]) -> float:
        """Ensure critical_max is greater than or equal to max."""
        max_val = values.get("max")
        if max_val is not None and critical_max < max_val:
            raise ValueError("Critical max value must be greater than or equal to max value")
        return critical_max
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "min": 60.0,
            "max": 100.0,
            "critical_min": 40.0,
            "critical_max": 140.0
        }
    })