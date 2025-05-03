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
    SUICIDE_ATTEMPT = "suicide_attempt"
    HOSPITALIZATION = "hospitalization"
    TREATMENT_DROPOUT = "treatment_dropout"

# --- Pydantic Models (Placeholders) ---

class BaseModelConfig(BaseModel):
    class Config:
        orm_mode = True # Or from_attributes = True for Pydantic v2
        extra = 'ignore' # Or model_config = {'extra': 'ignore'}

class ModelInfoRequest(BaseModelConfig):
    model_id: Optional[str] = None

class PerformanceMetrics(BaseModelConfig):
    auc: Optional[float] = None
    f1_score: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None

class ModelInfoResponse(BaseModelConfig):
    model_id: str
    model_type: str # Consider defining ModelType enum here if needed
    description: Optional[str] = None
    performance: Optional[PerformanceMetrics] = None

class RiskPredictionRequest(BaseModelConfig):
    patient_id: str
    features: Dict[str, Any]

class SideEffectRisk(BaseModelConfig):
    side_effect: str
    probability: float

class RiskPredictionResponse(BaseModelConfig):
    patient_id: str
    risk_type: RiskType
    risk_level: RiskLevel
    probability: float
    contributing_factors: Optional[List[str]] = None
    side_effect_risks: Optional[List[SideEffectRisk]] = None

class OutcomePredictionRequest(BaseModelConfig):
    patient_id: str
    treatment_context: Optional[Dict[str, Any]] = None
    features: Dict[str, Any]

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

class ExpectedOutcome(BaseModelConfig): # Placeholder for ExpectedOutcome structure
    outcome_details: List[OutcomeDetails]

class OutcomePredictionResponse(BaseModelConfig):
    patient_id: str
    expected_outcomes: List[OutcomeDetails] # Or ExpectedOutcome? Need clarity
    outcome_trajectories: Optional[List[OutcomeTrajectory]] = None
    response_likelihood: Optional[ResponseLikelihood] = None # Added based on imports
