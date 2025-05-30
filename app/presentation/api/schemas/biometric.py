"""
Biometric Schemas Module.

This module defines Pydantic models for biometric data validation,
serialization, and documentation in the presentation layer, ensuring
strict validation of all input and output data.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.domain.entities.biometric import BiometricType
from app.core.utils.date_utils import utcnow

# Corrected import path for BaseModelConfig
from app.presentation.api.schemas.base import BaseModelConfig


class BiometricBase(BaseModelConfig):
    """Base schema for biometric data with common fields."""

    biometric_type: BiometricType
    timestamp: datetime
    device_id: str | None = None
    metadata: dict[str, Any] | None = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v):
        """Ensure timestamp is not in the future."""
        if v > utcnow():
            raise ValueError("Timestamp cannot be in the future")
        return v


class BiometricCreateRequest(BiometricBase):
    """Request schema for creating a new biometric record."""

    value: dict[str, Any] = Field(..., description="Biometric measurements")


class BiometricUpdateRequest(BaseModelConfig):
    """Request schema for updating an existing biometric record."""

    biometric_type: BiometricType | None = None
    timestamp: datetime | None = None
    value: dict[str, Any] | None = None
    device_id: str | None = None
    metadata: dict[str, Any] | None = None


class BiometricResponse(BiometricBase):
    """Response schema for a detailed biometric record."""

    id: UUID
    value: dict[str, Any] = Field(..., description="Biometric measurements")
    user_id: UUID


class BiometricSummaryResponse(BaseModelConfig):
    """Response schema for a summarized biometric record."""

    id: UUID
    biometric_type: BiometricType
    timestamp: datetime
    device_id: str | None = None
    summary_value: dict[str, Any] = Field(..., description="Summarized biometric values")


class BiometricBatchItem(BiometricCreateRequest):
    """Schema for individual items in a batch upload."""

    pass


class BiometricBatchUploadRequest(BaseModelConfig):
    """Request schema for batch uploading multiple biometric records."""

    records: list[BiometricBatchItem] = Field(
        ..., description="List of biometric records to upload"
    )

    @field_validator("records")
    @classmethod
    def validate_records_length(cls, v):
        """Ensure records list has between 1 and 100 items."""
        if len(v) < 1:
            raise ValueError("At least one record is required")
        if len(v) > 100:
            raise ValueError("Maximum of 100 records allowed")
        return v
