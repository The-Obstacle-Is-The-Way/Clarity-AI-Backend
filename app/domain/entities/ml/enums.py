"""
Machine Learning model enums.

This module contains enumerations related to machine learning models
and their predictions.
"""

from enum import Enum


class ModelType(str, Enum):
    """
    Types of machine learning models supported by the system.
    """

    XGBOOST = "xgboost"
    LLM = "llm"
    TRANSFORMER = "transformer"
    REGRESSION = "regression"
    CLASSIFICATION = "classification"
    CLUSTERING = "clustering"
    RECOMMENDER = "recommender"
    NEURAL_NETWORK = "neural_network"
    PAT = "pat"  # Pretrained Actigraphy Transformer
    OTHER = "other"

    # Risk model types
    RISK_RELAPSE = "risk_relapse"
    RISK_SUICIDE = "risk_suicide"
    RISK_HOSPITALIZATION = "risk_hospitalization"

    # Treatment model types
    TREATMENT_MEDICATION_SSRI = "treatment_medication_ssri"
    TREATMENT_MEDICATION_SNRI = "treatment_medication_snri"
    TREATMENT_THERAPY_CBT = "treatment_therapy_cbt"

    # Outcome model types
    OUTCOME_DEPRESSION = "outcome_depression"
    OUTCOME_ANXIETY = "outcome_anxiety"
    OUTCOME_FUNCTIONAL = "outcome_functional"


class ResponseLevel(str, Enum):
    """
    Treatment response levels for psychiatric treatment predictions.
    """

    NONE = "none"
    MINIMAL = "minimal"
    PARTIAL = "partial"
    GOOD = "good"
    EXCELLENT = "excellent"


class RiskLevel(str, Enum):
    """
    Risk levels for risk assessment.
    """

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    IMMINENT = "imminent"


__all__ = ["ModelType", "ResponseLevel", "RiskLevel"]
