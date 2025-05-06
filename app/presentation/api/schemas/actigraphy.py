"""
Actigraphy API schema definitions.

This module defines the Pydantic models used for actigraphy data endpoints,
providing request/response schema validation for the API contract.
"""

from datetime import datetime
from enum import Enum
from typing import Any, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict


class AnalysisType(str, Enum):
    """Types of actigraphy analysis that can be performed."""
    SLEEP_QUALITY = "sleep_quality"
    ACTIVITY_PATTERNS = "activity_patterns"
    CIRCADIAN_RHYTHM = "circadian_rhythm"
    ENERGY_EXPENDITURE = "energy_expenditure"
    MOVEMENT_INTENSITY = "movement_intensity"
    ACTIVITY_LEVEL = "activity_level"
    ACTIVITY = "activity"
    SLEEP = "sleep"
    STRESS = "stress"


class SleepStage(str, Enum):
    """Sleep stages identified in actigraphy analysis."""
    AWAKE = "awake"
    LIGHT = "light"
    DEEP = "deep"
    REM = "rem"
    UNKNOWN = "unknown"


class BaseSchema(BaseModel):
    """Base schema with common configuration."""
    model_config = ConfigDict(from_attributes=True, extra="ignore")


class ActigraphyDataPoint(BaseSchema):
    """Individual actigraphy data point schema."""
    timestamp: datetime
    activity_count: int
    steps: int | None = None
    heart_rate: int | None = None
    light_level: float | None = None
    temperature: float | None = None
    position: str | None = None
    
    
class ActigraphyUploadRequest(BaseSchema):
    """Schema for uploading raw actigraphy data."""
    patient_id: str
    device_id: str
    device_type: str
    start_time: datetime
    end_time: datetime
    timezone: str
    data_points: list[ActigraphyDataPoint]
    metadata: dict[str, Any] | None = None


class ActigraphyUploadResponse(BaseSchema):
    """Schema for actigraphy upload response."""
    message: str
    file_id: str
    filename: str


class ActigraphyAnalysisRequest(BaseSchema):
    """Schema for requesting analysis of existing actigraphy data."""
    patient_id: str
    analysis_types: list[AnalysisType]
    start_time: datetime | None = None
    end_time: datetime | None = None
    parameters: dict[str, Any] | None = None


class SleepMetrics(BaseSchema):
    """Sleep metrics derived from actigraphy data."""
    total_sleep_time: float  # in minutes
    sleep_efficiency: float  # percentage
    sleep_latency: float  # in minutes
    wake_after_sleep_onset: float  # in minutes
    sleep_stage_duration: dict[SleepStage, float]  # in minutes
    number_of_awakenings: int


class ActivityMetrics(BaseSchema):
    """Activity metrics derived from actigraphy data."""
    total_steps: int
    active_minutes: float
    sedentary_minutes: float
    energy_expenditure: float  # in calories
    peak_activity_times: list[datetime]


class CircadianMetrics(BaseSchema):
    """Circadian rhythm metrics derived from actigraphy data."""
    rest_onset_time: datetime
    activity_onset_time: datetime
    rhythm_stability: float  # 0-1 scale
    interdaily_stability: float
    intradaily_variability: float


class ActigraphyAnalysisResult(BaseSchema):
    """Results of a specific type of actigraphy analysis."""
    analysis_type: AnalysisType
    analysis_time: datetime
    sleep_metrics: SleepMetrics | None = None
    activity_metrics: ActivityMetrics | None = None
    circadian_metrics: CircadianMetrics | None = None
    raw_results: dict[str, Any] | None = None


class AnalyzeActigraphyResponse(BaseSchema):
    """Schema for actigraphy analysis response."""
    analysis_id: uuid.UUID
    patient_id: str
    time_range: dict[str, datetime]
    results: list[ActigraphyAnalysisResult]


class ActigraphySummaryRequest(BaseSchema):
    """Schema for requesting a summary of actigraphy data over time."""
    patient_id: str
    start_date: datetime
    end_date: datetime
    interval: str = "day"  # day, week, month


class DailySummary(BaseSchema):
    """Daily summary of actigraphy metrics."""
    date: datetime
    total_sleep_time: float
    sleep_efficiency: float
    total_steps: int
    active_minutes: int
    energy_expenditure: float


class ActigraphySummaryResponse(BaseSchema):
    """Schema for actigraphy summary response."""
    patient_id: str
    interval: str
    summaries: list[DailySummary]
    trends: dict[str, float]  # e.g., "sleep_trend": 0.05 (positive trend)


class ActigraphyDataResponse(BaseSchema):
    data_id: str
    raw_data: Any
    metadata: dict
    timestamp: Optional[str] = None
    message: Optional[str] = None


class ActigraphyModelInfoResponse(BaseSchema):
    message: str
    version: str