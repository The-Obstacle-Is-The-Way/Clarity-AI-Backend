from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import ConfigDict, Field

from .base import BaseModelConfig

# --- Enums (defined here for API contract) ---


class RiskLevel(str, Enum):
    """Risk levels for psychiatric risk predictions (Presentation Layer)."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"


class ResponseLikelihood(str, Enum):  # Assuming this is an enum based on name
    """Likelihood of treatment response (Presentation Layer)."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


class OutcomeType(str, Enum):  # Assuming this is an enum
    """Type of outcome predicted (Presentation Layer)."""

    SYMPTOM_REDUCTION = "symptom_reduction"
    REMISSION = "remission"
    FUNCTIONAL_IMPROVEMENT = "functional_improvement"


class OutcomeDomain(str, Enum):  # Assuming this is an enum
    """Domain of the predicted outcome (Presentation Layer)."""

    DEPRESSION = "depression"
    ANXIETY = "anxiety"
    SUICIDALITY = "suicidality"
    OVERALL_FUNCTIONING = "overall_functioning"


class RiskType(str, Enum):
    """Types of mental health risks that can be predicted."""

    SUICIDE = "suicide"
    SUICIDE_ATTEMPT = "suicide_attempt"
    HOSPITALIZATION = "hospitalization"
    TREATMENT_DROPOUT = "treatment_dropout"
    SELF_HARM = "self_harm"
    VIOLENCE = "violence"
    SUBSTANCE_ABUSE = "substance_abuse"
    MEDICATION_NONCOMPLIANCE = "medication_noncompliance"
    RELAPSE = "relapse"  # Added for test compatibility


class TimeFrame(str, Enum):
    """Time frames for predictions and risk assessments (Presentation Layer)."""

    SHORT_TERM = "short_term"  # 0-30 days
    MEDIUM_TERM = "medium_term"  # 30-90 days
    LONG_TERM = "long_term"  # 90+ days


class TreatmentType(str, Enum):
    """Types of treatments that can be evaluated (Presentation Layer)."""

    MEDICATION = "medication"
    PSYCHOTHERAPY = "psychotherapy"
    THERAPY_CBT = "cognitive_behavioral_therapy"
    TMS = "transcranial_magnetic_stimulation"
    ECT = "electroconvulsive_therapy"
    LIFESTYLE = "lifestyle_intervention"


class VisualizationType(str, Enum):
    """Types of visualizations for model results (Presentation Layer)."""

    BAR_CHART = "bar_chart"
    LINE_CHART = "line_chart"
    SCATTER_PLOT = "scatter_plot"
    HEATMAP = "heatmap"
    NETWORK_GRAPH = "network_graph"
    RADAR_CHART = "radar_chart"


# --- Request/Response Models ---


class RiskPredictionRequest(BaseModelConfig):
    """Request model for risk prediction."""

    risk_type: RiskType
    patient_id: str
    patient_data: dict[str, Any] = Field(
        ..., description="Patient demographic and baseline data"
    )
    clinical_data: dict[str, Any] = Field(
        ..., description="Clinical data and measurements"
    )
    include_explainability: bool = False
    visualization_type: VisualizationType | None = None
    time_frame_days: int = Field(default=90, description="Prediction timeframe in days")
    confidence_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold for predictions",
    )

    # For backward compatibility with legacy code
    @property
    def duration_months(self) -> int:
        """Extract duration_months from clinical_data."""
        return self.clinical_data.get("duration_months", 6)

    @property
    def features(self) -> dict[str, Any]:
        """Combine patient_data and clinical_data for legacy code."""
        return {**self.patient_data, **self.clinical_data}


class RiskPredictionResponse(BaseModelConfig):
    """Response model for risk prediction."""

    prediction_id: str
    patient_id: str
    risk_type: RiskType
    risk_probability: float = Field(ge=0, le=1)
    risk_level: str
    risk_score: float = Field(ge=0, le=1)
    risk_factors: dict[str, float] = Field(default_factory=dict)
    confidence: float = Field(ge=0, le=1)
    timestamp: str
    time_frame_days: int
    # Fields for backward compatibility
    timeframe_months: int = 1
    prediction_date: datetime = Field(default_factory=datetime.now)
    feature_importance: dict[str, float] | None = None
    visualization_data: dict[str, Any] | None = None
    model_version: str = "1.0"

    model_config = ConfigDict(populate_by_name=True, protected_namespaces=())


class ModelInfoRequest(BaseModelConfig):
    """Request schema for retrieving model information."""

    model_id: str | None = None
    include_metrics: bool = False
    include_features: bool = False
    include_history: bool = False
    version: str | None = None


class PerformanceMetrics(BaseModelConfig):
    """Performance metrics for ML models."""

    accuracy: float = Field(ge=0.0, le=1.0, description="Overall accuracy of the model")
    precision: float = Field(ge=0.0, le=1.0, description="Precision metric")
    recall: float = Field(ge=0.0, le=1.0, description="Recall/sensitivity metric")
    f1_score: float = Field(
        ge=0.0, le=1.0, description="F1 score (harmonic mean of precision and recall)"
    )
    auc_roc: float | None = Field(
        None, ge=0.0, le=1.0, description="Area under ROC curve"
    )
    specificity: float | None = Field(
        None, ge=0.0, le=1.0, description="Specificity metric"
    )
    confusion_matrix: dict[str, int] | None = None
    cross_validation_scores: list[float] | None = None


class ModelInfoResponse(BaseModelConfig):
    """Response model for model information."""

    model_name: str
    model_type: str
    model_version: str
    creation_date: datetime
    training_dataset_size: int
    trained_for_domains: list[str]
    supports_features: list[str]
    description: str
    performance_metrics: PerformanceMetrics | None = None


class SideEffectRisk(BaseModelConfig):
    """Risk model for side effects.

    Can be used in two formats:
    1. Detail format with specific effect name, severity, and likelihood
    2. Categorized format with common and rare side effects
    """

    effect_name: str | None = None
    severity: str | None = None
    likelihood: float | None = None
    common: list[str] | None = Field(default_factory=list)
    rare: list[str] | None = Field(default_factory=list)


class TreatmentResponseRequest(BaseModelConfig):
    """Request schema for treatment response predictions."""

    patient_id: str
    treatment_type: TreatmentType
    treatment_id: str | None = None
    treatment_name: str | None = None
    time_frame: TimeFrame | None = None
    include_side_effects: bool = True
    features: dict[str, Any] = Field(default_factory=dict)
    baseline_severity: float | None = None  # For test compatibility


class OutcomeDetails(BaseModelConfig):
    domain: OutcomeDomain
    outcome_type: OutcomeType
    predicted_value: float | None = None
    probability: float | None = None
    confidence_interval: list[float] | None = None


class OutcomeTrajectoryPoint(BaseModelConfig):
    time_point: datetime  # Or int/float representing weeks/months
    predicted_value: float
    confidence_interval: list[float] | None = None


class OutcomeTrajectory(BaseModelConfig):
    domain: OutcomeDomain
    outcome_type: OutcomeType
    trajectory: list[OutcomeTrajectoryPoint]


class ExpectedOutcome(BaseModelConfig):
    """Expected outcome model for treatment response predictions."""

    outcome_details: list[OutcomeDetails] | None = None
    symptom_improvement: str | None = None
    time_to_response: str | None = None
    sustained_response_likelihood: ResponseLikelihood | None = None
    functional_improvement: str | None = None


class TherapyDetails(BaseModelConfig):
    """Details about a therapy or treatment."""

    therapy_id: str = "therapy_default_id"
    therapy_name: str = "Default Therapy Name"
    description: str | None = None
    typical_duration: int | None = None
    typical_frequency: int | None = None
    therapy_type: str | None = None
    is_medication: bool = False
    dosage: str | None = None
    side_effects: list[str] | None = None
    duration_weeks: int | None = None  # For test compatibility


class OutcomePredictionRequest(BaseModelConfig):
    """Request model for outcome prediction."""

    patient_id: str
    outcome_timeframe: dict[str, int] | None = None
    features: dict[str, Any] = Field(
        ..., description="Features used for the prediction model"
    )
    timeframe_days: int = Field(..., description="Prediction timeframe in days")
    clinical_data: dict[str, Any] | None = None
    treatment_plan: dict[str, Any] | None = None
    socioeconomic_factors: dict[str, Any] | None = None
    biometric_data: dict[str, Any] | None = None

    # Optional fields
    include_trajectories: bool = False
    include_recommendations: bool = True
    prediction_domains: list[str] | None = None
    prediction_types: list[str] | None = None


class OutcomePredictionResponse(BaseModelConfig):
    """Response schema for clinical outcome predictions."""

    patient_id: str
    expected_outcomes: list[OutcomeDetails]
    outcome_trajectories: list[OutcomeTrajectory] | None = None
    response_likelihood: ResponseLikelihood | None = None
    recommended_therapies: list[TherapyDetails] | None = None


class TreatmentResponseResponse(BaseModelConfig):
    """Response schema for treatment response predictions."""

    patient_id: str
    treatment_id: str
    treatment_name: str | None = None
    response_likelihood: ResponseLikelihood
    probability: float
    time_frame: TimeFrame
    expected_outcomes: list[OutcomeDetails]
    side_effects: list[SideEffectRisk] | None = None
    confidence_interval: list[float] | None = None


class XGBoostPredictionRequest(BaseModelConfig):
    """Request schema for XGBoost predictions."""

    patient_id: str = Field(..., description="Identifier for the patient")
    features: dict[str, Any] = Field(
        ..., description="Input features for the XGBoost model"
    )
    # Add other relevant fields if needed, e.g., context, specific model target


class XGBoostPredictionResponse(BaseModelConfig):
    """Response schema for XGBoost predictions."""

    prediction_id: str = Field(..., description="Unique identifier for this prediction")
    patient_id: str = Field(..., description="Identifier for the patient")
    prediction_value: float = Field(..., description="The raw prediction value/score")
    predicted_class: str | None = Field(
        None, description="Predicted class label, if applicable"
    )
    probability: float | None = Field(
        None, ge=0.0, le=1.0, description="Predicted probability, if applicable"
    )
    confidence: float | None = Field(
        None, ge=0.0, le=1.0, description="Confidence score for the prediction"
    )
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Timestamp of the prediction"
    )
    model_version: str = Field(..., description="Version of the XGBoost model used")
    feature_importance: dict[str, float] | None = Field(
        None, description="Feature importance scores, if available"
    )


class FeatureImportanceResponse(BaseModelConfig):
    """Response schema for feature importance explanations."""

    prediction_id: str = Field(
        ..., description="The ID of the prediction being explained"
    )
    patient_id: str = Field(..., description="The ID of the patient")
    features: dict[str, float] = Field(..., description="Feature importance scores")
    timestamp: str | datetime = Field(
        ..., description="Timestamp of when the explanation was generated"
    )
    model_version: str = Field(
        ..., description="Version of the model used for the prediction"
    )
    explanation_method: str = Field(
        default="SHAP", description="Method used to calculate feature importance"
    )
