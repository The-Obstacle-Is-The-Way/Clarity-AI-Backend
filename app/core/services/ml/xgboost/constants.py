"""
XGBoost service constants.

This module defines constants used by the XGBoost service implementations.
"""

from enum import Enum, auto

class ModelType(str, Enum):
    """Types of XGBoost models available in the system."""
    # Risk prediction models
    RISK_RELAPSE = "risk_relapse"
    RISK_SUICIDE = "risk_suicide" 
    RISK_HOSPITALIZATION = "risk_hospitalization"
    
    # Treatment response models
    TREATMENT_MEDICATION_SSRI = "treatment_medication_ssri"
    TREATMENT_MEDICATION_SNRI = "treatment_medication_snri"
    TREATMENT_THERAPY_CBT = "treatment_therapy_cbt"
    
    # Outcome prediction models
    OUTCOME_DEPRESSION = "outcome_depression"
    OUTCOME_ANXIETY = "outcome_anxiety"
    OUTCOME_FUNCTIONAL = "outcome_functional"

class EndpointType(str, Enum):
    """Types of XGBoost endpoints."""
    RISK_PREDICTION = "risk-prediction"
    TREATMENT_RESPONSE = "treatment-response"
    OUTCOME_PREDICTION = "outcome-prediction"
    MODEL_INFO = "model-info"
    FEATURE_IMPORTANCE = "feature-importance"
    DIGITAL_TWIN = "digital-twin"
