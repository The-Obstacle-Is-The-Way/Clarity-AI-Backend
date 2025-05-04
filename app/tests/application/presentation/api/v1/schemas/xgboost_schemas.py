"""
Minimal placeholder XGBoost schemas for integration tests.
Replace with real schemas as needed for production.
"""
from typing import Any

from pydantic import BaseModel, Field


class RiskPredictionRequest(BaseModel):
    """Request model for patient risk prediction."""
    patient_id: str = Field(..., description="Patient identifier")
    risk_type: str = Field(..., description="Type of risk to predict (e.g., relapse)")
    patient_data: dict[str, Any] = Field(..., description="Patient-provided data (e.g., demographics)")
    clinical_data: dict[str, Any] = Field(..., description="Clinical data for prediction")
    time_frame_days: int = Field(..., description="Time frame in days for risk prediction")

class RiskPredictionResponse(BaseModel):
    prediction_id: str
    risk_level: str
    risk_score: float
    confidence: float
    details: str | None = None
    time_frame_days: int | None = None

class TreatmentResponseRequest(BaseModel):
    patient_id: str = Field(...)
    treatment_type: str = Field(...)
    treatment_details: Any = Field(...)
    clinical_data: Any = Field(...)
    
# Request model for patient outcome prediction
class OutcomePredictionRequest(BaseModel):
    """Request model for patient outcome prediction."""
    patient_id: str = Field(..., description="Patient identifier")
    outcome_timeframe: Any = Field(..., description="Outcome timeframe for prediction")
    clinical_data: Any = Field(..., description="Clinical data for prediction")
    treatment_plan: Any = Field(..., description="Treatment plan data for prediction")

# Schema for model info requests
class ModelInfoRequest(BaseModel):
    """Request model for getting model information."""
    model_config = {"protected_namespaces": ()}
    model_type: str = Field(..., description="Type of model to retrieve information for")

# Schema for feature importance requests
class FeatureImportanceRequest(BaseModel):
    """Request model for getting feature importance."""
    model_config = {"protected_namespaces": ()}
    patient_id: str = Field(..., description="Patient identifier")
    model_type: str = Field(..., description="Type of model")
    prediction_id: str = Field(..., description="Prediction identifier to get feature importance for")

# Schema for digital twin integration requests
class DigitalTwinIntegrationRequest(BaseModel):
    """Request model for integrating with digital twin."""
    patient_id: str = Field(..., description="Patient identifier")
    profile_id: str = Field(..., description="Digital twin profile identifier")
    prediction_id: str = Field(..., description="Prediction identifier to integrate")

# Feature schema for model info response
class FeatureSchema(BaseModel):
    """Schema for model features."""
    name: str = Field(..., description="Feature name")
    importance: float = Field(..., description="Feature importance value")

# Performance metrics schema for model info response
class PerformanceMetricsSchema(BaseModel):
    """Schema for model performance metrics."""
    accuracy: float = Field(..., description="Model accuracy")
    f1_score: float = Field(..., description="Model F1 score")
    auc_roc: float = Field(..., description="Model AUC-ROC value")

# Schema for model info response
class ModelInfoResponse(BaseModel):
    """Response model for model information."""
    model_config = {"protected_namespaces": ()}
    model_type: str = Field(..., description="Type of model")
    version: str = Field(..., description="Model version")
    performance_metrics: PerformanceMetricsSchema = Field(..., description="Model performance metrics")
    features: list[FeatureSchema] = Field(..., description="Model features and their importance")
    description: str = Field(..., description="Model description")

