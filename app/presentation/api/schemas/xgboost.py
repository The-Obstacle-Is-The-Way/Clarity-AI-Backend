from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

# --- Enums (defined here for API contract) ---

class RiskLevel(str, Enum):
    """Risk levels for psychiatric risk predictions (Presentation Layer)."""
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"

class ResponseLikelihood(str, Enum): # Assuming this is an enum based on name
    """Likelihood of treatment response (Presentation Layer)."""
    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"

class OutcomeType(str, Enum): # Assuming this is an enum
    """Type of outcome predicted (Presentation Layer)."""
    SYMPTOM_REDUCTION = "symptom_reduction"
    REMISSION = "remission"
    FUNCTIONAL_IMPROVEMENT = "functional_improvement"

class OutcomeDomain(str, Enum): # Assuming this is an enum
    """Domain of the predicted outcome (Presentation Layer)."""
    DEPRESSION = "depression"
    ANXIETY = "anxiety"
    SUICIDALITY = "suicidality"
    OVERALL_FUNCTIONING = "overall_functioning"

class RiskType(str, Enum): # Assuming this is an enum
    """Type of risk predicted (Presentation Layer)."""
    SUICIDE = "suicide"
    SUICIDE_ATTEMPT = "suicide_attempt"
    HOSPITALIZATION = "hospitalization"
    TREATMENT_DROPOUT = "treatment_dropout"
    SELF_HARM = "self_harm"
    VIOLENCE = "violence"
    SUBSTANCE_ABUSE = "substance_abuse"
    MEDICATION_NONCOMPLIANCE = "medication_noncompliance"

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

# --- Base Model Configuration ---

class BaseModelConfig(BaseModel):
    """Base Pydantic model configuration."""
    class Config:
        populate_by_name = True
        from_attributes = True
        arbitrary_types_allowed = True

# --- Request/Response Models ---

class RiskPredictionRequest(BaseModelConfig):
    """Request model for risk prediction."""
    risk_type: RiskType
    patient_id: str
    patient_data: Dict[str, Any] = Field(..., description="Patient demographic and baseline data")
    clinical_data: Dict[str, Any] = Field(..., description="Clinical data and measurements")
    include_explainability: bool = False
    visualization_type: Optional[VisualizationType] = None
    
    # For backward compatibility with legacy code
    @property
    def duration_months(self) -> int:
        """Extract duration_months from clinical_data."""
        return self.clinical_data.get("duration_months", 6) 
    
    @property
    def features(self) -> Dict[str, Any]:
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
    risk_factors: Dict[str, float] = Field(default_factory=dict)
    confidence: float = Field(ge=0, le=1)
    timestamp: str
    time_frame_days: int
    # Fields for backward compatibility
    timeframe_months: int = 1
    prediction_date: datetime = Field(default_factory=datetime.now)
    feature_importance: Optional[Dict[str, float]] = None
    visualization_data: Optional[Dict[str, Any]] = None
    model_version: str = "1.0"
    
    class Config:
        populate_by_name = True

class ModelInfoRequest(BaseModelConfig):
    """Request schema for retrieving model information."""
    model_id: Optional[str] = None
    include_metrics: bool = False
    include_features: bool = False
    include_history: bool = False
    version: Optional[str] = None

class PerformanceMetrics(BaseModelConfig):
    """Performance metrics for ML models."""
    accuracy: float = Field(ge=0.0, le=1.0, description="Overall accuracy of the model")
    precision: float = Field(ge=0.0, le=1.0, description="Precision metric")
    recall: float = Field(ge=0.0, le=1.0, description="Recall/sensitivity metric")
    f1_score: float = Field(ge=0.0, le=1.0, description="F1 score (harmonic mean of precision and recall)")
    auc_roc: Optional[float] = Field(None, ge=0.0, le=1.0, description="Area under ROC curve")
    specificity: Optional[float] = Field(None, ge=0.0, le=1.0, description="Specificity metric")
    confusion_matrix: Optional[Dict[str, int]] = None
    cross_validation_scores: Optional[List[float]] = None

class ModelInfoResponse(BaseModelConfig):
    """Response model for model information."""
    model_name: str
    model_type: str
    model_version: str
    creation_date: datetime
    training_dataset_size: int
    trained_for_domains: List[str]
    supports_features: List[str]
    description: str
    performance_metrics: Optional[PerformanceMetrics] = None

class SideEffectRisk(BaseModelConfig):
    """Risk model for side effects.
    
    Can be used in two formats:
    1. Detail format with specific effect name, severity, and likelihood
    2. Categorized format with common and rare side effects
    """
    effect_name: Optional[str] = None
    severity: Optional[str] = None
    likelihood: Optional[float] = None
    common: Optional[List[str]] = Field(default_factory=list)
    rare: Optional[List[str]] = Field(default_factory=list)

class TreatmentResponseRequest(BaseModelConfig):
    """Request schema for treatment response predictions."""
    patient_id: str
    treatment_type: TreatmentType
    treatment_id: Optional[str] = None
    treatment_name: Optional[str] = None
    time_frame: Optional[TimeFrame] = None
    include_side_effects: bool = True
    features: Dict[str, Any] = Field(default_factory=dict)
    baseline_severity: Optional[float] = None  # For test compatibility

class OutcomeDetails(BaseModelConfig):
    domain: OutcomeDomain
    outcome_type: OutcomeType
    predicted_value: Optional[float] = None
    probability: Optional[float] = None
    confidence_interval: Optional[List[float]] = None

class OutcomeTrajectoryPoint(BaseModelConfig):
    time_point: datetime # Or int/float representing weeks/months
    predicted_value: float
    confidence_interval: Optional[List[float]] = None

class OutcomeTrajectory(BaseModelConfig):
    domain: OutcomeDomain
    outcome_type: OutcomeType
    trajectory: List[OutcomeTrajectoryPoint]

class ExpectedOutcome(BaseModelConfig):
    """Expected outcome model for treatment response predictions."""
    outcome_details: Optional[List[OutcomeDetails]] = None
    symptom_improvement: Optional[str] = None
    time_to_response: Optional[str] = None
    sustained_response_likelihood: Optional[ResponseLikelihood] = None
    functional_improvement: Optional[str] = None

class TherapyDetails(BaseModelConfig):
    """Details about a therapy or treatment."""
    therapy_id: str = "therapy_default_id"
    therapy_name: str = "Default Therapy Name"
    description: Optional[str] = None
    typical_duration: Optional[int] = None
    typical_frequency: Optional[int] = None
    therapy_type: Optional[str] = None
    is_medication: bool = False
    dosage: Optional[str] = None
    side_effects: Optional[List[str]] = None
    duration_weeks: Optional[int] = None  # For test compatibility

class OutcomePredictionRequest(BaseModelConfig):
    """Request schema for clinical outcome predictions."""
    patient_id: str
    timeframe_days: int = Field(ge=1, le=365, description="Prediction timeframe in days")
    prediction_domains: Optional[List[OutcomeDomain]] = None
    prediction_types: Optional[List[OutcomeType]] = None
    include_trajectories: bool = False
    include_recommendations: bool = False
    features: Dict[str, Any] = Field(..., description="Patient features for outcome prediction")

class OutcomePredictionResponse(BaseModelConfig):
    """Response schema for clinical outcome predictions."""
    patient_id: str
    expected_outcomes: List[OutcomeDetails]
    outcome_trajectories: Optional[List[OutcomeTrajectory]] = None
    response_likelihood: Optional[ResponseLikelihood] = None
    recommended_therapies: Optional[List[TherapyDetails]] = None

class TreatmentResponseResponse(BaseModelConfig):
    """Response schema for treatment response predictions."""
    patient_id: str
    treatment_id: str
    treatment_name: Optional[str] = None
    response_likelihood: ResponseLikelihood
    probability: float
    time_frame: TimeFrame
    expected_outcomes: List[OutcomeDetails]
    side_effects: Optional[List[SideEffectRisk]] = None
    confidence_interval: Optional[List[float]] = None