"""
Pretrained Actigraphy Transformer (PAT) data models.

This module defines the data models and schemas used by the PAT service.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator, ConfigDict


class AccelerometerReading(BaseModel):
    """Single accelerometer reading from a wearable device."""
    
    timestamp: datetime = Field(..., description="Timestamp of the reading")
    x: float = Field(..., description="X-axis acceleration value")
    y: float = Field(..., description="Y-axis acceleration value")
    z: float = Field(..., description="Z-axis acceleration value")
    
    @validator('timestamp')
    def ensure_timezone(cls, v):
        """Ensure timestamp has timezone information."""
        if v.tzinfo is None:
            return v.replace(tzinfo=datetime.now().astimezone().tzinfo)
        return v


class DeviceInfo(BaseModel):
    """Information about the wearable device."""
    
    device_id: str = Field(..., description="Unique identifier for the device")
    device_type: str = Field(..., description="Type of device (e.g., 'fitbit', 'apple_watch')")
    model: Optional[str] = Field(None, description="Device model")
    firmware_version: Optional[str] = Field(None, description="Device firmware version")
    sampling_rate_hz: float = Field(30.0, description="Sampling rate in Hz")


class PatientMetadata(BaseModel):
    """Patient metadata relevant for actigraphy analysis."""
    
    patient_id: str = Field(..., description="Unique identifier for the patient")
    age: Optional[int] = Field(None, description="Patient age in years")
    gender: Optional[str] = Field(None, description="Patient gender")
    height_cm: Optional[float] = Field(None, description="Patient height in centimeters")
    weight_kg: Optional[float] = Field(None, description="Patient weight in kilograms")
    diagnoses: Optional[List[str]] = Field(None, description="List of patient diagnoses")
    medications: Optional[List[Dict[str, Any]]] = Field(None, description="List of patient medications")


class AnalysisTypeEnum(str, Enum):
    """Types of actigraphy analysis."""
    
    SLEEP_QUALITY = "sleep_quality"
    ACTIVITY_PATTERNS = "activity_patterns"
    CIRCADIAN_RHYTHM = "circadian_rhythm"
    ENERGY_EXPENDITURE = "energy_expenditure"
    MENTAL_STATE_CORRELATION = "mental_state_correlation"
    MEDICATION_RESPONSE = "medication_response"


class PATModelSizeEnum(str, Enum):
    """Available PAT model sizes."""
    
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"


class AccelerometerDataRequest(BaseModel):
    """Request model for actigraphy data analysis."""
    
    readings: List[AccelerometerReading] = Field(..., description="List of accelerometer readings")
    device_info: DeviceInfo = Field(..., description="Information about the wearable device")
    patient_metadata: Optional[PatientMetadata] = Field(None, description="Patient metadata")
    analysis_type: AnalysisTypeEnum = Field(..., description="Type of analysis to perform")
    start_time: Optional[datetime] = Field(None, description="Start time for analysis window")
    end_time: Optional[datetime] = Field(None, description="End time for analysis window")
    model_size: PATModelSizeEnum = Field(PATModelSizeEnum.MEDIUM, description="PAT model size to use")
    cache_results: bool = Field(True, description="Whether to cache analysis results")


class AnalysisMetrics(BaseModel):
    """Base model for analysis metrics."""
    
    model_config = ConfigDict(extra="allow")


class SleepQualityMetrics(AnalysisMetrics):
    """Metrics for sleep quality analysis."""
    
    total_sleep_time: float = Field(..., description="Total sleep time in hours")
    sleep_efficiency: float = Field(..., description="Sleep efficiency as a percentage")
    sleep_latency: float = Field(..., description="Sleep latency in minutes")
    wake_after_sleep_onset: float = Field(..., description="Wake after sleep onset in minutes")
    rem_percentage: float = Field(..., description="REM sleep percentage")
    deep_sleep_percentage: float = Field(..., description="Deep sleep percentage")
    light_sleep_percentage: float = Field(..., description="Light sleep percentage")
    sleep_disruptions: int = Field(..., description="Number of sleep disruptions")


class ActivityPatternsMetrics(AnalysisMetrics):
    """Metrics for activity patterns analysis."""
    
    daily_step_count: int = Field(..., description="Estimated daily step count")
    sedentary_hours: float = Field(..., description="Hours of sedentary activity")
    light_activity_hours: float = Field(..., description="Hours of light activity")
    moderate_activity_minutes: float = Field(..., description="Minutes of moderate activity")
    vigorous_activity_minutes: float = Field(..., description="Minutes of vigorous activity")
    activity_regularity: float = Field(..., description="Regularity of activity patterns")


class CircadianRhythmMetrics(AnalysisMetrics):
    """Metrics for circadian rhythm analysis."""
    
    sleep_onset_time: str = Field(..., description="Typical sleep onset time (HH:MM)")
    wake_time: str = Field(..., description="Typical wake time (HH:MM)")
    rhythm_stability: float = Field(..., description="Stability of circadian rhythm")
    day_to_day_variation_minutes: float = Field(..., description="Day-to-day variation in minutes")
    social_jet_lag_hours: float = Field(..., description="Social jet lag in hours")
    light_exposure_morning_lux: float = Field(..., description="Morning light exposure in lux")


class EnergyExpenditureMetrics(AnalysisMetrics):
    """Metrics for energy expenditure analysis."""
    
    total_daily_energy_expenditure: int = Field(..., description="Total daily energy expenditure in kcal")
    base_metabolic_rate: int = Field(..., description="Base metabolic rate in kcal")
    active_energy_expenditure: int = Field(..., description="Active energy expenditure in kcal")
    activity_level_factor: float = Field(..., description="Activity level factor")
    peak_energy_hour: int = Field(..., description="Hour of peak energy expenditure")


class MentalStateCorrelationMetrics(AnalysisMetrics):
    """Metrics for mental state correlation analysis."""
    
    activity_mood_correlation: float = Field(..., description="Correlation between activity and mood")
    sleep_anxiety_correlation: float = Field(..., description="Correlation between sleep and anxiety")
    circadian_stability_mood_correlation: float = Field(..., description="Correlation between circadian stability and mood")
    activity_variability_stress_correlation: float = Field(..., description="Correlation between activity variability and stress")
    depression_risk_score: float = Field(..., description="Depression risk score")
    anxiety_risk_score: float = Field(..., description="Anxiety risk score")


class MedicationResponseMetrics(AnalysisMetrics):
    """Metrics for medication response analysis."""
    
    pre_post_activity_change: float = Field(..., description="Change in activity pre/post medication")
    pre_post_sleep_change: float = Field(..., description="Change in sleep pre/post medication")
    pre_post_circadian_change: float = Field(..., description="Change in circadian rhythm pre/post medication")
    side_effect_probability: float = Field(..., description="Probability of medication side effects")
    response_trajectory: str = Field(..., description="Trajectory of medication response")
    days_to_observable_change: int = Field(..., description="Days to observable change")


class AnalysisResult(BaseModel):
    """Result of actigraphy data analysis."""
    
    analysis_id: str = Field(..., description="Unique identifier for the analysis")
    patient_id: Optional[str] = Field(None, description="Patient identifier")
    analysis_type: AnalysisTypeEnum = Field(..., description="Type of analysis performed")
    timestamp: datetime = Field(..., description="Timestamp of the analysis")
    model_version: str = Field(..., description="Version of the PAT model used")
    confidence_score: float = Field(..., description="Confidence score for the analysis")
    metrics: Dict[str, Any] = Field(..., description="Analysis metrics")
    insights: List[str] = Field(..., description="Insights derived from the analysis")
    warnings: List[str] = Field([], description="Warnings or alerts from the analysis")
    
    @validator('metrics', pre=True)
    def validate_metrics(cls, v, values):
        """Validate metrics based on analysis type."""
        if 'analysis_type' not in values:
            return v
            
        analysis_type = values['analysis_type']
        
        # This is just a validation check, not enforcing specific schema
        # In a real implementation, we would validate against the appropriate metrics model
        required_keys = {
            AnalysisTypeEnum.SLEEP_QUALITY: ['total_sleep_time', 'sleep_efficiency'],
            AnalysisTypeEnum.ACTIVITY_PATTERNS: ['daily_step_count', 'sedentary_hours'],
            AnalysisTypeEnum.CIRCADIAN_RHYTHM: ['sleep_onset_time', 'wake_time', 'rhythm_stability'],
            AnalysisTypeEnum.ENERGY_EXPENDITURE: ['total_daily_energy_expenditure', 'base_metabolic_rate'],
            AnalysisTypeEnum.MENTAL_STATE_CORRELATION: ['depression_risk_score', 'anxiety_risk_score'],
            AnalysisTypeEnum.MEDICATION_RESPONSE: ['pre_post_activity_change', 'pre_post_sleep_change']
        }
        
        if analysis_type in required_keys:
            for key in required_keys[analysis_type]:
                if key not in v:
                    raise ValueError(f"Missing required metric '{key}' for analysis type '{analysis_type}'")
        
        return v


class HistoricalAnalysisRequest(BaseModel):
    """Request model for retrieving historical analysis results."""
    
    patient_id: str = Field(..., description="Patient identifier")
    analysis_type: Optional[AnalysisTypeEnum] = Field(None, description="Type of analysis to filter by")
    start_date: Optional[datetime] = Field(None, description="Start date for filtering results")
    end_date: Optional[datetime] = Field(None, description="End date for filtering results")
    limit: int = Field(10, description="Maximum number of results to return")
    skip: int = Field(0, description="Number of results to skip")


class ModelInfoResponse(BaseModel):
    """Response model for PAT model information."""
    
    model_config = ConfigDict(protected_namespaces=())
    
    model_name: str = Field(..., description="Name of the PAT model")
    model_size: PATModelSizeEnum = Field(..., description="Size of the PAT model")
    model_path: str = Field(..., description="Path to the PAT model")
    parameters: str = Field(..., description="Number of model parameters")
    supported_analysis_types: List[str] = Field(..., description="Supported analysis types")
    gpu_enabled: bool = Field(..., description="Whether GPU acceleration is enabled")
    cache_enabled: bool = Field(..., description="Whether result caching is enabled")