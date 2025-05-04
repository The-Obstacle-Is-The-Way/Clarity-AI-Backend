"""
Pydantic schemas for the XGBoost service API.

This module defines the request and response schemas for the XGBoost service API,
ensuring proper validation and documentation of API inputs and outputs.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# -------------------- Enum Definitions --------------------

class RiskType(str, Enum):
    """Types of risk that can be predicted."""
    
    RELAPSE = "relapse"
    SUICIDE = "suicide"
    HOSPITALIZATION = "hospitalization"


class RiskLevel(str, Enum):
    """Risk level classifications."""
    
    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


class TreatmentType(str, Enum):
    """Types of treatments that can be evaluated."""
    
    MEDICATION_SSRI = "medication_ssri"
    MEDICATION_SNRI = "medication_snri"
    MEDICATION_ATYPICAL = "medication_atypical"
    THERAPY_CBT = "therapy_cbt"
    THERAPY_DBT = "therapy_dbt"
    THERAPY_IPT = "therapy_ipt"
    THERAPY_PSYCHODYNAMIC = "therapy_psychodynamic"


class ResponseLikelihood(str, Enum):
    """Likelihood of response to treatment."""
    
    POOR = "poor"
    LIMITED = "limited"
    MODERATE = "moderate"
    GOOD = "good"
    EXCELLENT = "excellent"


class OutcomeType(str, Enum):
    """Types of outcomes that can be predicted."""
    
    SYMPTOM = "symptom"
    FUNCTIONAL = "functional"
    QUALITY_OF_LIFE = "quality_of_life"


class VisualizationType(str, Enum):
    """Types of visualizations for predictions."""
    
    BAR_CHART = "bar_chart"
    LINE_CHART = "line_chart"
    RADAR_CHART = "radar_chart"
    HEATMAP = "heatmap"


# -------------------- Base Models --------------------

class BaseResponse(BaseModel):
    """Base model for all response schemas."""
    
    model_config = ConfigDict(extra="ignore")
class ErrorResponse(BaseResponse):
    """Schema for error responses."""
    
    error: str = Field(..., description="Error message")
    error_type: str = Field(..., description="Type of error")
    details: dict[str, Any] | None = Field(None, description="Additional error details")
    field: str | None = Field(None, description="Field that caused the error, if applicable")
    value: Any | None = Field(None, description="Value that caused the error, if applicable")


class TimeFrame(BaseModel):
    """Schema for specifying a time frame."""
    
    days: int | None = Field(None, ge=0, description="Number of days")
    weeks: int | None = Field(None, ge=0, description="Number of weeks")
    months: int | None = Field(None, ge=0, description="Number of months")
    
    @model_validator(mode="after")
    @classmethod
    def validate_at_least_one(cls, m):
        """Validate that at least one time unit is provided."""
        if m.days is None and m.weeks is None and m.months is None:
            raise ValueError("At least one time unit (days, weeks, months) must be provided")
        return m


# -------------------- Risk Prediction --------------------

class RiskPredictionRequest(BaseModel):
    """Schema for risk prediction requests."""
    
    patient_id: str = Field(..., description="Patient identifier")
    # Use str for risk_type to allow model lookup to handle unknown types
    risk_type: str = Field(..., description="Type of risk to predict")
    clinical_data: dict[str, Any] = Field(..., description="Clinical data for prediction")
    patient_data: dict[str, Any] = Field(default_factory=dict, description="Patient demographic data for prediction")
    temporal_data: dict[str, Any] | None = Field(None, description="Temporal data for prediction")
    confidence_threshold: float = Field(0.5, description="Confidence threshold for prediction")
    time_frame_days: int | None = Field(None, description="Time frame in days for prediction")
    
    model_config = ConfigDict(extra="allow")


class RiskFactor(BaseModel):
    """Schema for risk factors."""
    
    name: str = Field(..., description="Name of the risk factor")
    weight: str = Field(..., description="Weight or importance of the factor")


class RiskFactors(BaseModel):
    """Schema for risk factor collections."""
    
    contributing_factors: list[RiskFactor] = Field(default_factory=list, description="Factors that contribute to risk")
    protective_factors: list[RiskFactor] = Field(default_factory=list, description="Factors that reduce risk")


class SupportingEvidence(BaseModel):
    """Schema for supporting evidence items."""
    
    factor: str = Field(..., description="Factor name")
    impact: str = Field(..., description="Impact level (high, moderate, low)")
    description: str = Field(..., description="Description of the evidence")


class RiskPredictionResponse(BaseResponse):
    """Schema for risk prediction responses."""
    
    prediction_id: str = Field(..., description="Unique identifier for the prediction")
    patient_id: str = Field(..., description="Patient identifier")
    risk_type: RiskType = Field(..., description="Type of risk predicted")
    risk_level: RiskLevel = Field(..., description="Predicted risk level")
    risk_score: float = Field(..., ge=0, le=1, description="Numerical risk score")
    confidence: float = Field(..., ge=0, le=1, description="Confidence in the prediction")
    supporting_evidence: list[SupportingEvidence] = Field(default_factory=list, description="Evidence supporting the prediction")
    risk_factors: RiskFactors = Field(..., description="Risk factors identified")
    features: dict[str, Any] = Field(default_factory=dict, description="Features used in the prediction")
    timestamp: str = Field(..., description="Timestamp of the prediction")
    time_frame_days: int = Field(..., ge=1, description="Time frame for prediction in days")

    @field_validator('timestamp', mode='before')
    @classmethod
    def format_timestamp(cls, v):
        if isinstance(v, datetime):
            return v.strftime('%Y-%m-%dT%H:%M:%SZ')
        return v


# -------------------- Treatment Response Prediction --------------------

class MedicationDetails(BaseModel):
    """Schema for medication treatment details."""
    
    medication: str = Field(..., description="Name of the medication")
    dose_mg: float | None = Field(None, gt=0, description="Dose in milligrams")
    frequency: str | None = Field(None, description="Frequency of administration")
    
    model_config = ConfigDict(extra="allow")


class TherapyDetails(BaseModel):
    """Schema for therapy treatment details."""
    
    frequency: str = Field(..., description="Frequency of sessions (weekly, twice_weekly, monthly)")
    duration_minutes: int | None = Field(None, gt=0, description="Duration of each session in minutes")
    modality: str | None = Field(None, description="Therapy modality (individual, group)")
    
    model_config = ConfigDict(extra="allow")


class TreatmentResponseRequest(BaseModel):
    """Schema for treatment response prediction requests."""
    
    patient_id: str = Field(..., description="Patient identifier")
    treatment_type: TreatmentType = Field(..., description="Type of treatment")
    treatment_details: MedicationDetails | TherapyDetails | dict[str, Any] = Field(
        ...,
        description="Treatment details"
    )
    clinical_data: dict[str, Any] = Field(..., description="Clinical data for prediction")
    prediction_horizon: str | None = Field("8_weeks", description="Time horizon for prediction")
    genetic_data: list[Any] = Field(default_factory=list, description="Genetic data for prediction")
    treatment_history: list[dict[str, Any]] = Field(default_factory=list, description="Treatment history")

    @field_validator('treatment_type', mode='before')
    @classmethod
    def parse_treatment_type(cls, v):
        # Allow simplified treatment type inputs (e.g., 'ssri' for 'medication_ssri')
        if isinstance(v, str):
            norm = v.lower()
            for member in TreatmentType:
                if norm == member.value:
                    return member
                # allow suffix match (e.g., 'ssri', 'cbt')
                if norm == member.value.split('_')[-1]:
                    return member
        return v

    model_config = ConfigDict(extra="allow")


class SideEffect(BaseModel):
    """Schema for side effect information."""
    
    effect: str = Field(..., description="Name of the side effect")
    likelihood: str = Field(..., description="Likelihood of occurrence")
    severity: str = Field(..., description="Severity of the side effect")


class SideEffectRisk(BaseModel):
    """Schema for side effect risk collections."""
    
    common: list[SideEffect] = Field(default_factory=list, description="Common side effects")
    rare: list[SideEffect] = Field(default_factory=list, description="Rare side effects")


class ExpectedOutcome(BaseModel):
    """Schema for expected treatment outcomes."""
    
    symptom_improvement: str = Field(..., description="Expected symptom improvement")
    time_to_response: str = Field(..., description="Expected time to response")
    sustained_response_likelihood: ResponseLikelihood = Field(..., description="Likelihood of sustained response")
    functional_improvement: str = Field(..., description="Expected functional improvement")


class TreatmentResponseResponse(BaseResponse):
    """Schema for treatment response prediction responses."""
    
    prediction_id: str = Field(..., description="Unique identifier for the prediction")
    patient_id: str = Field(..., description="Patient identifier")
    treatment_type: TreatmentType = Field(..., description="Type of treatment")
    treatment_details: dict[str, Any] = Field(..., description="Treatment details")
    response_likelihood: ResponseLikelihood = Field(..., description="Likelihood of positive response")
    efficacy_score: float = Field(..., ge=0, le=1, description="Numerical efficacy score")
    confidence: float = Field(..., ge=0, le=1, description="Confidence in the prediction")
    expected_outcome: ExpectedOutcome = Field(..., description="Expected outcome details")
    side_effect_risk: SideEffectRisk = Field(..., description="Side effect risk assessment")
    features: dict[str, Any] = Field(default_factory=dict, description="Clinical features used in the prediction")
    treatment_features: dict[str, Any] = Field(default_factory=dict, description="Treatment features used in the prediction")
    timestamp: str = Field(..., description="Timestamp of the prediction")
    prediction_horizon: str = Field(..., description="Time horizon for prediction")

    @field_validator('timestamp', mode='before')
    @classmethod
    def format_timestamp(cls, v):
        if isinstance(v, datetime):
            return v.strftime('%Y-%m-%dT%H:%M:%SZ')
        return v


# -------------------- Outcome Prediction --------------------

class OutcomePredictionRequest(BaseModel):
    """Schema for outcome prediction requests."""
    
    patient_id: str = Field(..., description="Patient identifier")
    outcome_timeframe: TimeFrame = Field(..., description="Timeframe for outcome prediction")
    clinical_data: dict[str, Any] = Field(..., description="Clinical data for prediction")
    treatment_plan: dict[str, Any] = Field(..., description="Treatment plan details")
    social_determinants: dict[str, Any] = Field(default_factory=dict, description="Social determinants data for prediction")
    comorbidities: list[str] = Field(default_factory=list, description="Comorbidities list for prediction")
    outcome_type: OutcomeType | None = Field(OutcomeType.SYMPTOM, description="Type of outcome to predict")
    
    model_config = ConfigDict(extra="allow")


class OutcomeTrajectoryPoint(BaseModel):
    """Schema for a point in an outcome trajectory."""
    
    time_point: str = Field(..., description="Name of the time point")
    days_from_start: int = Field(..., ge=0, description="Days from start of treatment")
    improvement_percentage: int = Field(..., ge=0, le=100, description="Percentage improvement at this point")


class OutcomeTrajectory(BaseModel):
    """Schema for outcome trajectory data."""
    
    points: list[OutcomeTrajectoryPoint] = Field(..., description="Trajectory points")
    final_improvement: int = Field(..., ge=0, le=100, description="Final improvement percentage")
    time_frame_days: int = Field(..., ge=1, description="Time frame in days")
    visualization_type: VisualizationType = Field(..., description="Visualization type for the trajectory")


class OutcomeDomain(BaseModel):
    """Schema for an outcome domain."""
    
    name: str = Field(..., description="Name of the domain")
    improvement: str = Field(..., description="Expected improvement in this domain")
    notes: str = Field(..., description="Additional notes")


class OutcomeDetails(BaseModel):
    """Schema for detailed outcome information."""
    
    overall_improvement: str = Field(..., description="Overall expected improvement")
    domains: list[OutcomeDomain] = Field(..., description="Domain-specific outcomes")
    recommendations: list[str] = Field(..., description="Treatment recommendations")


class OutcomePredictionResponse(BaseResponse):
    """Schema for outcome prediction responses."""
    
    prediction_id: str = Field(..., description="Unique identifier for the prediction")
    patient_id: str = Field(..., description="Patient identifier")
    outcome_type: OutcomeType = Field(..., description="Type of outcome predicted")
    outcome_score: float = Field(..., ge=0, le=1, description="Numerical outcome score")
    time_frame_days: int = Field(..., ge=1, description="Time frame in days")
    confidence: float = Field(..., ge=0, le=1, description="Confidence in the prediction")
    trajectory: OutcomeTrajectory = Field(..., description="Outcome trajectory over time")
    outcome_details: OutcomeDetails = Field(..., description="Detailed outcome information")
    features: dict[str, Any] = Field(default_factory=dict, description="Clinical features used in the prediction")
    treatment_features: dict[str, Any] = Field(default_factory=dict, description="Treatment features used in the prediction")
    timestamp: str = Field(..., description="Timestamp of the prediction")

    @field_validator('timestamp', mode='before')
    @classmethod
    def format_timestamp(cls, v):
        if isinstance(v, datetime):
            return v.strftime('%Y-%m-%dT%H:%M:%SZ')
        return v


# -------------------- Feature Importance --------------------

class FeatureImportanceRequest(BaseModel):
    """Schema for feature importance requests."""
    
    model_config = {"protected_namespaces": ()}
    
    patient_id: str = Field(..., description="Patient identifier")
    model_type: str = Field(..., description="Type of model")
    prediction_id: str = Field(..., description="Prediction identifier")


class VisualizationData(BaseModel):
    """Schema for visualization data."""
    
    labels: list[str] = Field(..., description="Chart labels")
    values: list[float] = Field(..., description="Chart values")


class Visualization(BaseModel):
    """Schema for visualization information."""
    
    type: VisualizationType = Field(..., description="Type of visualization")
    data: VisualizationData = Field(..., description="Visualization data")


class FeatureImportanceResponse(BaseResponse):
    """Schema for feature importance responses."""
    
    model_config = {"protected_namespaces": ()}
    
    prediction_id: str = Field(..., description="Prediction identifier")
    patient_id: str = Field(..., description="Patient identifier")
    model_type: str = Field(..., description="Type of model")
    feature_importance: dict[str, float] = Field(..., description="Feature importance values")
    visualization: Visualization = Field(..., description="Visualization data")
    timestamp: str = Field(..., description="Timestamp of the feature importance calculation")

    @field_validator('timestamp', mode='before')
    @classmethod
    def format_timestamp(cls, v):
        if isinstance(v, datetime):
            return v.strftime('%Y-%m-%dT%H:%M:%SZ')
        return v
    
    model_config = {"protected_namespaces": ()}


# -------------------- Digital Twin Integration --------------------

class DigitalTwinIntegrationRequest(BaseModel):
    """Schema for digital twin integration requests."""
    
    patient_id: str = Field(..., description="Patient identifier")
    profile_id: str = Field(..., description="Digital twin profile identifier")
    prediction_id: str = Field(..., description="Prediction identifier")


class DigitalTwinIntegrationResponse(BaseResponse):
    """Schema for digital twin integration responses."""
    
    profile_id: str = Field(..., description="Digital twin profile identifier")
    patient_id: str = Field(..., description="Patient identifier")
    prediction_id: str = Field(..., description="Prediction identifier")
    status: str = Field(..., description="Integration status")
    timestamp: str = Field(..., description="Timestamp of the integration")

    @field_validator('timestamp', mode='before')
    @classmethod
    def format_timestamp(cls, v):
        if isinstance(v, datetime):
            return v.strftime('%Y-%m-%dT%H:%M:%SZ')
        return v
    recommendations_generated: bool = Field(..., description="Whether recommendations were generated")
    statistics_updated: bool = Field(..., description="Whether statistics were updated")


# -------------------- Model Information --------------------

class ModelInfoRequest(BaseModel):
    """Schema for model information requests."""
    
    model_config = {"protected_namespaces": ()}
    
    model_type: str = Field(..., description="Type of model")


class PerformanceMetrics(BaseModel):
    """Schema for model performance metrics."""
    
    accuracy: float = Field(..., ge=0, le=1, description="Accuracy metric")
    precision: float = Field(..., ge=0, le=1, description="Precision metric")
    recall: float = Field(..., ge=0, le=1, description="Recall metric")
    f1_score: float = Field(..., ge=0, le=1, description="F1 score")
    auc_roc: float = Field(..., ge=0, le=1, description="Area under ROC curve")


class ModelInfoResponse(BaseResponse):
    """Schema for model information responses."""
    
    model_config = {"protected_namespaces": ()}
    
    model_type: str = Field(..., description="Type of model")
    version: str = Field(..., description="Model version")
    last_updated: str = Field(..., description="Last update timestamp")
    description: str = Field(..., description="Model description")

    @field_validator('last_updated', mode='before')
    @classmethod
    def format_last_updated(cls, v):
        if isinstance(v, datetime):
            return v.strftime('%Y-%m-%dT%H:%M:%SZ')
        return v
    features: list[str] = Field(..., description="Features used by the model")
    performance_metrics: PerformanceMetrics = Field(..., description="Performance metrics")
    hyperparameters: dict[str, Any] = Field(..., description="Model hyperparameters")
    status: str = Field(..., description="Model status")
    hyperparameters: dict[str, Any] = Field(..., description="Model hyperparameters")
    status: str = Field(..., description="Model status")
