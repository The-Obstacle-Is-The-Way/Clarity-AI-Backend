"""
Biometric data schemas for the Clarity AI API.

This module provides Pydantic models for validating and serializing biometric data
in API requests and responses, following Clean Architecture principles.
"""

from datetime import datetime
from typing import Any, ClassVar
from uuid import UUID

from pydantic import BaseModel, Field, validator

from app.core.utils.date_utils import utcnow


class BiometricDataPoint(BaseModel):
    """Schema for a single biometric data point."""

    id: UUID
    patient_id: UUID
    biometric_type: str = Field(..., description="Type of biometric measurement")
    value: float = Field(..., description="Recorded value of the measurement")
    unit: str = Field(..., description="Unit of measurement")
    timestamp: datetime = Field(..., description="When the measurement was taken")
    source: str | None = Field(None, description="Source of the measurement (e.g., device model)")
    metadata: dict[str, Any] | None = Field(
        default_factory=dict, description="Additional metadata about the measurement"
    )

    class Config:
        """Pydantic configuration."""

        orm_mode = True
        schema_extra: ClassVar[dict] = {
            "example": {
                "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "patient_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "biometric_type": "heart_rate",
                "value": 72.5,
                "unit": "bpm",
                "timestamp": "2025-05-01T12:00:00Z",
                "source": "FitMonitor X7",
                "metadata": {"position": "resting", "confidence": 0.95}
            }
        }


class BiometricCreateRequest(BaseModel):
    """Schema for creating a new biometric data point."""

    patient_id: UUID
    biometric_type: str = Field(..., description="Type of biometric measurement")
    value: float = Field(..., description="Recorded value of the measurement")
    unit: str = Field(..., description="Unit of measurement")
    timestamp: datetime | None = Field(None, description="When the measurement was taken")
    source: str | None = Field(None, description="Source of the measurement (e.g., device model)")
    metadata: dict[str, Any] | None = Field(
        default_factory=dict, description="Additional metadata about the measurement"
    )

    class Config:
        """Pydantic configuration."""

        schema_extra = {
            "example": {
                "patient_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "biometric_type": "heart_rate",
                "value": 72.5,
                "unit": "bpm",
                "timestamp": "2025-05-01T12:00:00Z",
                "source": "FitMonitor X7",
                "metadata": {"position": "resting", "confidence": 0.95}
            }
        }

    @validator("timestamp", pre=True, always=True)
    def set_timestamp_now(cls, v: Any) -> datetime:
        """Set timestamp to current time if not provided."""
        return v or utcnow()


class BiometricUpdateRequest(BaseModel):
    """Schema for updating an existing biometric data point."""

    biometric_type: str | None = Field(None, description="Type of biometric measurement")
    value: float | None = Field(None, description="Recorded value of the measurement")
    unit: str | None = Field(None, description="Unit of measurement")
    timestamp: datetime | None = Field(None, description="When the measurement was taken")
    source: str | None = Field(None, description="Source of the measurement")
    metadata: dict[str, Any] | None = Field(None, description="Additional metadata")

    class Config:
        """Pydantic configuration."""

        schema_extra = {
            "example": {
                "value": 73.2,
                "metadata": {"position": "active", "confidence": 0.92}
            }
        }


class BiometricListMeta(BaseModel):
    """Metadata for biometric list responses."""

    total: int
    limit: int
    offset: int
    timestamp: datetime = Field(default_factory=utcnow)


class BiometricListResponse(BaseModel):
    """Schema for a list of biometric data points."""

    items: list[BiometricDataPoint]
    total: int
    limit: int
    offset: int
    meta: dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        schema_extra = {
            "example": {
                "items": [
                    {
                        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        "patient_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        "biometric_type": "heart_rate",
                        "value": 72.5,
                        "unit": "bpm",
                        "timestamp": "2025-05-01T12:00:00Z",
                        "source": "FitMonitor X7",
                        "metadata": {"position": "resting", "confidence": 0.95}
                    }
                ],
                "total": 1,
                "limit": 100,
                "offset": 0,
                "meta": {"timestamp": "2025-05-01T12:05:00Z"}
            }
        }


class BiometricResponse(BaseModel):
    """Schema for a single biometric data point response."""

    biometric: BiometricDataPoint
    meta: dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        schema_extra = {
            "example": {
                "biometric": {
                    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                    "patient_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                    "biometric_type": "heart_rate",
                    "value": 72.5,
                    "unit": "bpm",
                    "timestamp": "2025-05-01T12:00:00Z",
                    "source": "FitMonitor X7",
                    "metadata": {"position": "resting", "confidence": 0.95}
                },
                "meta": {"requested_at": "2025-05-01T12:05:00Z"}
            }
        }


class BiometricStatistics(BaseModel):
    """Schema for biometric statistics."""

    min: float
    max: float
    avg: float
    median: float
    count: int
    start_date: datetime
    end_date: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        schema_extra = {
            "example": {
                "min": 65.2,
                "max": 142.7,
                "avg": 78.3,
                "median": 72.5,
                "count": 248,
                "start_date": "2025-04-01T00:00:00Z",
                "end_date": "2025-05-01T00:00:00Z",
                "metadata": {"confidence": 0.95}
            }
        }


class BiometricStatisticsResponse(BaseModel):
    """Schema for a biometric statistics response."""

    statistics: BiometricStatistics
    biometric_type: str
    patient_id: UUID
    meta: dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration."""

        schema_extra = {
            "example": {
                "statistics": {
                    "min": 65.2,
                    "max": 142.7,
                    "avg": 78.3,
                    "median": 72.5,
                    "count": 248,
                    "start_date": "2025-04-01T00:00:00Z",
                    "end_date": "2025-05-01T00:00:00Z",
                    "metadata": {"confidence": 0.95}
                },
                "biometric_type": "heart_rate",
                "patient_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "meta": {"calculated_at": "2025-05-01T12:05:00Z"}
            }
        }
