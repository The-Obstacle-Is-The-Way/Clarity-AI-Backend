"""
Biometric Schemas Module.

This module defines Pydantic models for biometric data validation,
serialization, and documentation in the presentation layer, ensuring
strict validation of all input and output data.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, validator

from app.core.domain.entities.biometric import BiometricType

# Corrected import path for BaseModelConfig
from app.presentation.api.schemas.xgboost import BaseModelConfig


class BiometricBase(BaseModelConfig):
    """Base schema for biometric data with common fields."""
    biometric_type: BiometricType
    timestamp: datetime
    device_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @validator("timestamp")
    def validate_timestamp(cls, v):
        """Ensure timestamp is not in the future."""
        if v > datetime.now():
            raise ValueError("Timestamp cannot be in the future")
        return v


class BiometricCreateRequest(BiometricBase):
    """Request schema for creating a new biometric record."""
    value: Dict[str, Any] = Field(..., description="Biometric measurements")


class BiometricUpdateRequest(BaseModelConfig):
    """Request schema for updating an existing biometric record."""
    biometric_type: Optional[BiometricType] = None
    timestamp: Optional[datetime] = None
    value: Optional[Dict[str, Any]] = None
    device_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BiometricResponse(BiometricBase):
    """Response schema for a detailed biometric record."""
    id: UUID
    value: Dict[str, Any] = Field(..., description="Biometric measurements")
    user_id: UUID


class BiometricSummaryResponse(BaseModelConfig):
    """Response schema for a summarized biometric record."""
    id: UUID
    biometric_type: BiometricType
    timestamp: datetime
    device_id: Optional[str] = None
    summary_value: Dict[str, Any] = Field(..., description="Summarized biometric values")


class BiometricBatchItem(BiometricCreateRequest):
    """Schema for individual items in a batch upload."""
    pass


class BiometricBatchUploadRequest(BaseModelConfig):
    """Request schema for batch uploading multiple biometric records."""
    records: List[BiometricBatchItem] = Field(..., min_items=1, max_items=100)
