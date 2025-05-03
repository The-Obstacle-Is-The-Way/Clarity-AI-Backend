"""
Actigraphy API schema definitions.

This module defines the Pydantic models used for actigraphy data endpoints,
providing request/response schema validation for the API contract.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class AnalysisType(str, Enum):
    """Types of actigraphy analysis that can be performed."""
    SLEEP_QUALITY = "sleep_quality"
    ACTIVITY_PATTERNS = "activity_patterns"
    CIRCADIAN_RHYTHM = "circadian_rhythm"
    ENERGY_EXPENDITURE = "energy_expenditure"
    MOVEMENT_INTENSITY = "movement_intensity"


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
    steps: Optional[int] = None
    heart_rate: Optional[int] = None
    light_level: Optional[float] = None
    temperature: Optional[float] = None
    position: Optional[str] = None
    
    
class ActigraphyUploadRequest(BaseSchema):
    """Schema for uploading raw actigraphy data."""
    patient_id: str
    device_id: str
    device_type: str
    start_time: datetime
    end_time: datetime
    timezone: str
    data_points: List[ActigraphyDataPoint]
    metadata: Optional[Dict[str, Any]] = None


class ActigraphyUploadResponse(BaseSchema):
    """Schema for actigraphy upload response."""
    success: bool
    record_id: str
    message: str
    data_points_processed: int


class ActigraphyAnalysisRequest(BaseSchema):
    """Schema for requesting analysis of existing actigraphy data."""
    patient_id: str
    analysis_types: List[AnalysisType]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    parameters: Optional[Dict[str, Any]] = None


class SleepMetrics(BaseSchema):
    """Sleep metrics derived from actigraphy data."""
    total_sleep_time: float  # in minutes
    sleep_efficiency: float  # percentage
    sleep_latency: float  # in minutes
    wake_after_sleep_onset: float  # in minutes
    sleep_stage_duration: Dict[SleepStage, float]  # in minutes
    number_of_awakenings: int


class ActivityMetrics(BaseSchema):
    """Activity metrics derived from actigraphy data."""
    total_steps: int
    active_minutes: float
    sedentary_minutes: float
    energy_expenditure: float  # in calories
    peak_activity_times: List[datetime]


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
    sleep_metrics: Optional[SleepMetrics] = None
    activity_metrics: Optional[ActivityMetrics] = None
    circadian_metrics: Optional[CircadianMetrics] = None
    raw_results: Optional[Dict[str, Any]] = None


class ActigraphyAnalysisResponse(BaseSchema):
    """Schema for actigraphy analysis response."""
    patient_id: str
    time_range: Dict[str, datetime]
    results: List[ActigraphyAnalysisResult]


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
    summaries: List[DailySummary]
    trends: Dict[str, float]  # e.g., "sleep_trend": 0.05 (positive trend)