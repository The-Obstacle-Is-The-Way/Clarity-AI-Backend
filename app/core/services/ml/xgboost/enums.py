"""
Enums for the XGBoost service module.

This module defines various enumeration types used throughout
the XGBoost service for consistent type-safe categorization
of predictions, risk levels, and treatment categories.
"""

from enum import Enum


class ResponseLevel(str, Enum):
    """Treatment response levels for psychiatric treatment predictions."""
    
    NONE = "none"
    MINIMAL = "minimal"
    PARTIAL = "partial"
    GOOD = "good"
    EXCELLENT = "excellent"


class PredictionType(str, Enum):
    """Types of predictions that can be made by XGBoost models."""
    
    RISK = "risk"
    TREATMENT_RESPONSE = "treatment_response"
    OUTCOME = "outcome"
    FEATURE_IMPORTANCE = "feature_importance"


class RiskLevel(str, Enum):
    """Risk levels for psychiatric risk predictions."""
    
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"


class TreatmentCategory(str, Enum):
    """Categories of psychiatric treatments."""
    
    MEDICATION_SSRI = "medication_ssri"
    MEDICATION_SNRI = "medication_snri"
    MEDICATION_ATYPICAL = "medication_atypical"
    MEDICATION_MOOD_STABILIZER = "medication_mood_stabilizer"
    MEDICATION_ANTIPSYCHOTIC = "medication_antipsychotic"
    THERAPY_CBT = "therapy_cbt"
    THERAPY_DBT = "therapy_dbt"
    THERAPY_IPT = "therapy_ipt"
    THERAPY_PSYCHODYNAMIC = "therapy_psychodynamic"
    ECT = "ect"
    TMS = "tms"
    HOSPITALIZATION = "hospitalization"
    COMBINATION = "combination"