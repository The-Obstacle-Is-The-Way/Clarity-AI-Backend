"""
Core domain enums for ML model types.

This module defines the standardized model types used across the system.
Following clean architecture principles, these enums exist in the core domain layer
to maintain consistency across all application layers.
"""
from enum import Enum


class ModelType(Enum):
    """
    Enumeration of supported ML model types in the system.
    
    This enum centralizes all model type definitions to ensure consistency
    across domain, application, and infrastructure layers.
    """
    RISK = "risk"
    TREATMENT_RESPONSE = "treatment_response"
    SYMPTOM_PREDICTION = "symptom_prediction"
    MEDICATION_EFFICACY = "medication_efficacy"
    RELAPSE_RISK = "relapse_risk"
    DIGITAL_TWIN = "digital_twin"
    PHARMACOGENOMICS = "pharmacogenomics"
    XGBOOST = "xgboost"
    CUSTOM = "custom"
    
    def __str__(self) -> str:
        """String representation of the model type."""
        return self.value
