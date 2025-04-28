"""
Biometric Twin domain entities.

This module defines the domain entities for the biometric twin feature,
including biometric data points and related concepts.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from app.domain.utils.datetime_utils import UTC
from typing import Any, ClassVar
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator
from typing_extensions import Annotated


class BiometricDataPoint(BaseModel):
    """
    Represents a single biometric data point collected from a patient.
    
    This entity is a core component of the Digital Twin model, capturing real-time
    physiological measurements that can be used for clinical insights and alerts.
    Based on the digital twin research in psychiatry (Frontiers in Psychiatry, 2023),
    each data point includes metadata for contextual understanding and confidence
    scores for reliability assessment.
    """
    
    data_id: UUID | str = Field(
        ..., 
        description="Unique identifier for the data point"
    )
    patient_id: UUID | None = Field(
        ...,
        description="ID of the patient this data belongs to"
    )
    data_type: str = Field(
        ..., 
        description="Type of biometric data (e.g., heart_rate, blood_pressure, sleep_quality)"
    )
    value: float = Field(
        ..., 
        description="Numerical value of the data point"
    )
    timestamp: datetime = Field(
        ..., 
        description="Time when the data was recorded"
    )
    source: str = Field(
        ..., 
        description="Source of the data (e.g., apple_watch, fitbit, manual_entry)"
    )
    metadata: dict[str, Any] | None = Field(
        None, 
        description="Additional contextual information about the data point"
    )
    confidence: float | None = Field(
        None, 
        description="Confidence score for the data point (0.0 to 1.0)"
    )
    
    @field_validator('data_type')
    @classmethod
    def validate_data_type(cls, v: str) -> str:
        """Validate that the data type is one of the allowed values."""
        allowed_types = [
            "heart_rate", "blood_pressure", "respiratory_rate", 
            "sleep_quality", "sleep_duration", "steps", "activity_level",
            "mood_score", "anxiety_level", "stress_level", "medication_adherence",
            "blood_glucose", "weight", "temperature", "oxygen_saturation",
            "hrv", "cortisol_level", "social_interaction"
        ]
        
        if v not in allowed_types:
            raise ValueError(f"Data type must be one of {allowed_types}")
        return v
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v: float | None) -> float | None:
        """Validate that the confidence score is between 0 and 1."""
        if v is not None and (v < 0.0 or v > 1.0):
            raise ValueError("Confidence score must be between 0.0 and 1.0")
        return v
    
    def to_dict(self) -> dict[str, Any]:
        """Convert the data point to a dictionary, sanitizing PHI as needed."""
        result = self.dict(exclude={"metadata"})
        
        # Include only safe metadata fields if present
        if self.metadata:
            safe_metadata = {
                k: v for k, v in self.metadata.items() 
                if k in ["activity", "position", "device_info", "clinical_context"]
            }
            if safe_metadata:
                result["metadata"] = safe_metadata
        
        return result


class BiometricTwinState(BaseModel):
    """
    Represents the current state of a patient's biometric digital twin.
    
    The digital twin state aggregates multiple biometric data points and derived
    insights to create a comprehensive virtual representation of the patient's
    physiological and psychological state, enabling predictive modeling and
    personalized interventions as described in psychiatric digital twin research.
    """
    
    patient_id: UUID = Field(..., description="ID of the patient")
    last_updated: datetime = Field(..., description="Timestamp of the last update")
    data_points: dict[str, list[BiometricDataPoint]] = Field(
        default_factory=dict,
        description="Dictionary of data points by type"
    )
    derived_metrics: dict[str, Any] = Field(
        default_factory=dict,
        description="Metrics derived from the raw data points"
    )
    clinical_insights: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Clinical insights generated from the biometric data"
    )
    risk_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Risk scores for various clinical concerns"
    )
    
    def add_data_point(self, data_point: BiometricDataPoint) -> None:
        """Add a new data point to the digital twin state."""
        data_type = data_point.data_type
        if data_type not in self.data_points:
            self.data_points[data_type] = []
        
        self.data_points[data_type].append(data_point)
        self.last_updated = datetime.now(UTC)
    
    def get_latest_value(self, data_type: str) -> float | None:
        """Get the latest value for a specific data type."""
        if data_type not in self.data_points or not self.data_points[data_type]:
            return None
        
        # Sort by timestamp and get the most recent
        latest_point = sorted(
            self.data_points[data_type], 
            key=lambda x: x.timestamp,
            reverse=True
        )[0]
        
        return latest_point.value
    
    def to_dict(self) -> dict[str, Any]:
        """Convert the twin state to a dictionary, sanitizing PHI as needed."""
        result = {
            "patient_id": str(self.patient_id),
            "last_updated": self.last_updated.isoformat(),
            "data_types": list(self.data_points.keys()),
            "derived_metrics": self.derived_metrics,
            "risk_scores": self.risk_scores
        }
        
        # Include sanitized clinical insights
        safe_insights = []
        for insight in self.clinical_insights:
            safe_insight = {
                k: v for k, v in insight.items()
                if k not in ["raw_data", "detailed_analysis"]
            }
            safe_insights.append(safe_insight)
        
        result["clinical_insights"] = safe_insights
        
        return result
