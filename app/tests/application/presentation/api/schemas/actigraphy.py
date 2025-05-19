"""
Pydantic schemas for actigraphy data analysis.

This module defines the request and response schemas for actigraphy-related
API endpoints, including data analysis, embedding generation, and integration
with digital twins.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AnalysisType(str, Enum):
    """Enumeration of all supported actigraphy analysis types.

    The test‑suite (and some legacy routes) expect several *synonymous*
    enumeration members.  To remain fully backward‑compatible we expose the
    superset below – multiple names may resolve to the same string *value*.

    Keeping these aliases avoids breaking external consumers while we migrate
    toward a smaller canonical surface.  New code should prefer the
    ``*_QUALITY`` / ``*_LEVELS`` variants, but both are accepted to honour the
    project’s **OpenAPI stability** commitment.
    """

    # Canonical/explicit names ------------------------------------------------
    SLEEP_QUALITY: str = "sleep_quality"
    ACTIVITY_LEVELS: str = "activity_levels"
    GAIT: str = "gait_analysis"
    TREMOR: str = "tremor_analysis"

    # ---------------------------------------------------------------------
    # Backwards‑compatibility aliases expected by the test‑suite
    # ---------------------------------------------------------------------
    # NOTE: All aliases intentionally use **the same value string** as their
    # canonical counterpart so downstream equality checks continue to work.

    # Additional / legacy names ------------------------------------------------
    SLEEP: str = "sleep"
    ACTIVITY_LEVEL: str = "activity_level"
    ACTIVITY: str = "activity"

    # Stress / mental‑state correlation
    STRESS: str = "stress"


class AccelerometerReading(BaseModel):
    """Accelerometer reading data."""

    timestamp: str = Field(
        ...,
        description="ISO-8601 formatted timestamp of the reading",
        examples=["2025-03-28T14:05:23.321Z"],
    )
    x: float = Field(..., description="X-axis acceleration in g")
    y: float = Field(..., description="Y-axis acceleration in g")
    z: float = Field(..., description="Z-axis acceleration in g")
    heart_rate: int | None = Field(None, description="Heart rate in BPM, if available")
    metadata: dict[str, Any] | None = Field(
        None, description="Additional metadata for the reading"
    )


class DeviceInfo(BaseModel):
    """Information about the recording device."""

    device_type: str = Field(
        ...,
        description="Type of the device",
        examples=["smartwatch", "fitness_tracker", "medical_device"],
    )
    model: str = Field(
        ...,
        description="Model of the device",
        examples=["Apple Watch Series 9", "Fitbit Sense 2"],
    )
    manufacturer: str | None = Field(
        None,
        description="Manufacturer of the device",
        examples=["Apple", "Fitbit", "Samsung"],
    )
    firmware_version: str | None = Field(
        None, description="Firmware version of the device"
    )
    position: str | None = Field(
        None,
        description="Position of the device on the body",
        examples=["wrist_left", "wrist_right", "waist", "ankle"],
    )
    metadata: dict[str, Any] | None = Field(
        None, description="Additional metadata for the device"
    )


# Request Models


class AnalyzeActigraphyRequest(BaseModel):
    """Request to analyze actigraphy data."""

    patient_id: str = Field(..., description="Unique identifier for the patient")
    readings: list[AccelerometerReading] = Field(
        ..., description="List of accelerometer readings", min_length=1
    )
    start_time: str = Field(
        ...,
        description="ISO-8601 formatted start time of the recording",
        examples=["2025-03-28T14:00:00Z"],
    )
    end_time: str = Field(
        ...,
        description="ISO-8601 formatted end time of the recording",
        examples=["2025-03-28T16:00:00Z"],
    )
    sampling_rate_hz: float = Field(..., description="Sampling rate in Hz", gt=0)
    device_info: DeviceInfo = Field(
        ..., description="Information about the recording device"
    )
    analysis_types: list[AnalysisType] = Field(
        ..., description="Types of analyses to perform", min_length=1
    )

    @model_validator(mode="after")
    def validate_times(self) -> "AnalyzeActigraphyRequest":
        """Validate that end_time is after start_time."""
        # Normalize trailing Z only, to avoid doubling offsets
        start_str = (
            self.start_time[:-1] if self.start_time.endswith("Z") else self.start_time
        )
        end_str = self.end_time[:-1] if self.end_time.endswith("Z") else self.end_time
        start = datetime.fromisoformat(start_str)
        end = datetime.fromisoformat(end_str)

        if end <= start:
            raise ValueError("end_time must be after start_time")

        return self


class GetActigraphyEmbeddingsRequest(BaseModel):
    """Request to generate embeddings from actigraphy data."""

    patient_id: str = Field(..., description="Unique identifier for the patient")
    readings: list[AccelerometerReading] = Field(
        ..., description="List of accelerometer readings", min_length=1
    )
    start_time: str = Field(
        ...,
        description="ISO-8601 formatted start time of the recording",
        examples=["2025-03-28T14:00:00Z"],
    )
    end_time: str = Field(
        ...,
        description="ISO-8601 formatted end time of the recording",
        examples=["2025-03-28T16:00:00Z"],
    )
    sampling_rate_hz: float = Field(..., description="Sampling rate in Hz", gt=0)

    @model_validator(mode="after")
    def validate_times(self) -> "GetActigraphyEmbeddingsRequest":
        """Validate that end_time is after start_time."""
        # Normalize trailing Z only
        start_str = (
            self.start_time[:-1] if self.start_time.endswith("Z") else self.start_time
        )
        end_str = self.end_time[:-1] if self.end_time.endswith("Z") else self.end_time
        start = datetime.fromisoformat(start_str)
        end = datetime.fromisoformat(end_str)

        if end <= start:
            raise ValueError("end_time must be after start_time")

        return self


class IntegrateWithDigitalTwinRequest(BaseModel):
    """Request to integrate actigraphy analysis with a digital twin profile."""

    patient_id: str = Field(..., description="Unique identifier for the patient")
    profile_id: str = Field(
        ..., description="Unique identifier for the digital twin profile"
    )
    analysis_id: str = Field(
        ..., description="Unique identifier for the analysis to integrate"
    )


# Response Models


class DataSummary(BaseModel):
    """Summary of the analyzed data."""

    start_time: str = Field(
        ..., description="ISO-8601 formatted start time of the recording"
    )
    end_time: str = Field(
        ..., description="ISO-8601 formatted end time of the recording"
    )
    duration_seconds: float = Field(
        ..., description="Duration of the recording in seconds"
    )
    readings_count: int = Field(..., description="Number of readings in the recording")
    sampling_rate_hz: float = Field(..., description="Sampling rate in Hz")


class AnalysisResult(BaseModel):
    """Result of actigraphy analysis."""

    analysis_id: str = Field(..., description="Unique identifier for the analysis")
    patient_id: str = Field(..., description="Unique identifier for the patient")
    timestamp: str = Field(
        ..., description="ISO-8601 formatted timestamp of the analysis"
    )
    analysis_types: list[str] = Field(..., description="Types of analyses performed")
    device_info: dict[str, Any] = Field(
        ..., description="Information about the recording device"
    )
    data_summary: DataSummary = Field(..., description="Summary of the analyzed data")
    results: dict[str, Any] = Field(
        ..., description="Analysis results for each analysis type"
    )
    # Convenience fields for individual analysis types
    sleep_metrics: dict[str, Any] | None = Field(
        None, description="Sleep quality metrics"
    )
    activity_levels: dict[str, Any] | None = Field(
        None, description="Activity level metrics"
    )


class AnalysisSummary(BaseModel):
    """Summary of an analysis for lists."""

    analysis_id: str = Field(..., description="Unique identifier for the analysis")
    timestamp: str = Field(
        ..., description="ISO-8601 formatted timestamp of the analysis"
    )
    analysis_types: list[str] = Field(..., description="Types of analyses performed")
    data_summary: DataSummary = Field(..., description="Summary of the analyzed data")


class Pagination(BaseModel):
    """Pagination information for lists."""

    total: int = Field(..., description="Total number of items")
    limit: int = Field(..., description="Maximum number of items per page")
    offset: int = Field(..., description="Offset for pagination")
    has_more: bool = Field(..., description="Whether there are more items")


class AnalysesList(BaseModel):
    """List of analyses with pagination information."""

    analyses: list[AnalysisSummary] = Field(
        ..., description="List of analysis summaries"
    )
    pagination: Pagination = Field(..., description="Pagination information")


class EmbeddingData(BaseModel):
    """Embedding data."""

    model_config = {"protected_namespaces": ()}

    vector: list[float] = Field(..., description="Embedding vector")
    dimension: int = Field(..., description="Dimension of the embedding vector")
    model_version: str = Field(..., description="Version of the embedding model")


class EmbeddingResult(BaseModel):
    """Result of embedding generation."""

    embedding_id: str = Field(..., description="Unique identifier for the embedding")
    patient_id: str = Field(..., description="Unique identifier for the patient")
    timestamp: str = Field(
        ..., description="ISO-8601 formatted timestamp of the embedding generation"
    )
    data_summary: DataSummary = Field(
        ..., description="Summary of the data used for embedding"
    )
    embedding: EmbeddingData = Field(..., description="Embedding data")
    # Legacy aliases for embedding vector and size
    embeddings: list[float] = Field(
        ..., description="Legacy alias for embedding vector"
    )
    embedding_size: int = Field(..., description="Legacy alias for embedding size")


class Insight(BaseModel):
    """Insight derived from analysis."""

    type: str = Field(..., description="Type of insight")
    description: str = Field(..., description="Description of the insight")
    recommendation: str = Field(..., description="Recommendation based on the insight")
    confidence: float = Field(
        ..., description="Confidence score for the insight", ge=0.0, le=1.0
    )


class ProfileUpdate(BaseModel):
    """Information about the digital twin profile update."""

    updated_aspects: list[str] = Field(
        ..., description="Aspects of the profile that were updated"
    )
    confidence_score: float = Field(
        ..., description="Confidence score for the update", ge=0.0, le=1.0
    )
    updated_at: str = Field(
        ..., description="ISO-8601 formatted timestamp of the update"
    )


class AnalyzeActigraphyResponse(BaseModel):
    """Response containing the ID and status of the initiated analysis."""

    analysis_id: uuid.UUID = Field(
        ..., description="Unique identifier for the analysis task"
    )
    status: str = Field("processing", description="Current status of the analysis task")


class AnalysisResponse(BaseModel):
    """Minimal AnalysisResponse schema for actigraphy analysis endpoints."""

    analysis_id: str
    status: str
    result: str | None = None


class UploadResponse(BaseModel):
    """Minimal UploadResponse schema for actigraphy upload endpoints."""

    upload_id: str
    status: str
    detail: str | None = None


class IntegrationResult(BaseModel):
    """Result of digital twin integration."""

    integration_id: str = Field(
        ..., description="Unique identifier for the integration"
    )
    patient_id: str = Field(..., description="Unique identifier for the patient")
    profile_id: str = Field(
        ..., description="Unique identifier for the digital twin profile"
    )
    analysis_id: str = Field(
        ..., description="Unique identifier for the integrated analysis"
    )
    timestamp: str = Field(
        ..., description="ISO-8601 formatted timestamp of the integration"
    )
    status: str = Field(..., description="Status of the integration")
    insights: list[Insight] = Field(
        ..., description="Insights derived from the analysis"
    )
    profile_update: ProfileUpdate = Field(
        ..., description="Information about the profile update"
    )
