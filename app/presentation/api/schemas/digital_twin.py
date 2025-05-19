"""
Digital Twin Schemas Module.

This module defines Pydantic models for digital twin data validation,
serialization, and documentation in the presentation layer, ensuring
strict validation of all input and output data for HIPAA compliance.
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import ConfigDict, Field

from app.core.domain.entities.digital_twin import SimulationType, TwinType
from app.presentation.api.schemas.base import BaseModelConfig


class DigitalTwinBase(BaseModelConfig):
    """Base schema for digital twin data with common fields."""

    twin_type: TwinType
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = Field(None, max_length=1000)


class DigitalTwinCreateRequest(DigitalTwinBase):
    """Request schema for creating a new digital twin."""

    data: dict[str, Any] = Field(..., description="Digital twin model data")
    patient_id: str | None = None  # For provider-created twins


class DigitalTwinUpdateRequest(BaseModelConfig):
    """Request schema for updating an existing digital twin."""

    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = Field(None, max_length=1000)
    version: str | None = None
    data: dict[str, Any] | None = None


class DigitalTwinResponse(DigitalTwinBase):
    """Response schema for digital twin data."""

    id: UUID
    created_at: datetime
    updated_at: datetime
    version: str
    data: dict[str, Any] | None = None
    user_id: str  # The ID of the patient this digital twin belongs to
    profile_summary: str | None = None
    current_state: str | None = None


class TwinSimulationRequest(BaseModelConfig):
    """Request schema for running a digital twin simulation."""

    simulation_type: SimulationType
    parameters: dict[str, Any] = Field(..., description="Simulation parameters")
    timeframe_days: int = Field(
        30, ge=1, le=365, description="Simulation timeframe in days"
    )


class TwinSimulationResponse(BaseModelConfig):
    """Response schema for digital twin simulation results."""

    simulation_id: str
    twin_id: str
    simulation_type: SimulationType
    executed_at: datetime
    timeframe_days: int
    results: dict[str, Any]


# New schemas for digital twin endpoints


class ComponentStatus(BaseModelConfig):
    """Schema for the status of a digital twin component."""

    has_model: bool | None = None
    last_updated: datetime | None = None
    service_available: bool | None = None
    service_info: dict[str, Any] | None = None


class DigitalTwinStatusResponse(BaseModelConfig):
    """Response schema for digital twin status."""

    patient_id: str
    status: str  # "complete", "partial", "initializing", etc.
    completeness: int = Field(
        ..., ge=0, le=100, description="Percentage of completeness"
    )
    components: dict[str, ComponentStatus]
    last_checked: datetime

    # Modern Pydantic V2 configuration using ConfigDict
    model_config = ConfigDict(
        json_schema_extra={
            "json_encoders": {
                # Format datetime fields as required by the tests
                datetime: lambda v: v.isoformat()
            }
        }
    )


class SymptomTrend(BaseModelConfig):
    """Schema for a symptom trend."""

    symptom: str
    trend: str  # "increasing", "decreasing", "stable"
    confidence: float = Field(..., ge=0, le=1)
    insight_text: str


class RiskAlert(BaseModelConfig):
    """Schema for a risk alert."""

    symptom: str
    risk_level: str  # "low", "moderate", "high"
    alert_text: str
    importance: float = Field(..., ge=0, le=1)


class BiometricCorrelation(BaseModelConfig):
    """Schema for a biometric correlation."""

    biometric_type: str
    mental_health_indicator: str
    correlation_strength: float = Field(..., ge=0, le=1)
    direction: str  # "positive", "negative"
    insight_text: str
    p_value: float | None = None


class MedicationPrediction(BaseModelConfig):
    """Schema for a medication response prediction."""

    medication: str
    predicted_response: str  # "positive", "negative", "neutral"
    confidence: float = Field(..., ge=0, le=1)


class Recommendation(BaseModelConfig):
    """Schema for a recommendation."""

    source: str  # "integrated", "forecasting", "biometric", etc.
    type: str  # "biometric_symptom", "medication_adjustment", etc.
    recommendation: str
    importance: float = Field(..., ge=0, le=1)


class MedicationResponsePredictions(BaseModelConfig):
    """Schema for medication response predictions."""

    predictions: list[MedicationPrediction]


class SymptomForecasting(BaseModelConfig):
    """Schema for symptom forecasting."""

    trending_symptoms: list[SymptomTrend]
    risk_alerts: list[RiskAlert]


class BiometricCorrelations(BaseModelConfig):
    """Schema for biometric correlations."""

    strong_correlations: list[BiometricCorrelation]


class PharmacogenomicsData(BaseModelConfig):
    """Schema for pharmacogenomics data."""

    medication_responses: MedicationResponsePredictions


class PersonalizedInsightResponse(BaseModelConfig):
    """Response schema for personalized insights."""

    insight_id: str | None = None
    digital_twin_id: str
    patient_id: str | None = None
    query: str | None = None
    insight_type: str | None = None
    insight: str | None = None
    key_points: list[str] | None = None
    confidence: float | None = Field(None, ge=0, le=1)
    timestamp: datetime | None = None
    generated_at: datetime | None = None
    symptom_forecasting: SymptomForecasting | None = None
    biometric_correlation: BiometricCorrelations | None = None
    pharmacogenomics: PharmacogenomicsData | None = None
    integrated_recommendations: list[Recommendation] | None = None

    # Modern Pydantic V2 configuration using ConfigDict
    model_config = ConfigDict(
        json_schema_extra={
            "json_encoders": {
                # Format datetime fields as required by the tests
                datetime: lambda v: v.isoformat()
            }
        }
    )


class AnalysisType(str, Enum):
    """Types of clinical text analysis."""

    SUMMARY = "summary"
    SYMPTOM_EXTRACTION = "symptom_extraction"
    DIAGNOSIS_SUGGESTION = "diagnosis_suggestion"
    TREATMENT_RECOMMENDATION = "treatment_recommendation"
    RISK_ASSESSMENT = "risk_assessment"


class ClinicalTextAnalysisRequest(BaseModelConfig):
    """Request schema for clinical text analysis."""

    text: str = Field(..., min_length=1)
    analysis_type: AnalysisType = Field(AnalysisType.SUMMARY)
    additional_context: dict[str, Any] | None = None


class ClinicalTextAnalysisResponse(BaseModelConfig):
    """Response schema for clinical text analysis."""

    analysis_type: AnalysisType
    result: str
    metadata: dict[str, Any] | None = None
    confidence: float | None = Field(None, ge=0, le=1)
    insights: list[str] | None = None
