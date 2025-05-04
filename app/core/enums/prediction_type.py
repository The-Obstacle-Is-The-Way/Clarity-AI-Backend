"""
Core domain enums for prediction types and categories.

This module defines the standardized prediction types used across the system.
Following clean architecture principles, these enums exist in the core domain layer
to maintain consistency across all application layers.
"""
from enum import Enum


class PredictionCategory(Enum):
    """
    Enumeration of supported prediction categories in the system.
    
    This categorizes predictions by their general purpose or application area.
    """
    RISK = "risk"
    TREATMENT = "treatment"
    SYMPTOM = "symptom"
    MEDICATION = "medication"
    OUTCOME = "outcome"
    DIGITAL_TWIN = "digital_twin"
    CUSTOM = "custom"
    
    def __str__(self) -> str:
        """String representation of the prediction category."""
        return self.value


class PredictionType(Enum):
    """
    Enumeration of specific prediction types available in the system.
    
    This provides more granular classification than PredictionCategory and
    maps to specific model implementations and endpoints.
    """
    # Risk predictions
    SUICIDE_RISK = "suicide_risk"
    HOSPITALIZATION_RISK = "hospitalization_risk"
    RELAPSE_RISK = "relapse_risk"
    CRISIS_RISK = "crisis_risk"
    
    # Treatment predictions
    MEDICATION_RESPONSE = "medication_response"
    THERAPY_RESPONSE = "therapy_response"
    TREATMENT_ADHERENCE = "treatment_adherence"
    
    # Symptom predictions
    SYMPTOM_TRAJECTORY = "symptom_trajectory"
    SYMPTOM_SEVERITY = "symptom_severity"
    SYMPTOM_CLUSTER = "symptom_cluster"
    
    # Outcome predictions
    FUNCTIONAL_OUTCOME = "functional_outcome"
    QUALITY_OF_LIFE = "quality_of_life"
    RECOVERY_TIMELINE = "recovery_timeline"
    
    # Digital twin specific
    NEUROTRANSMITTER_DYNAMICS = "neurotransmitter_dynamics"
    BRAIN_NETWORK_RESPONSE = "brain_network_response"
    RECEPTOR_SENSITIVITY = "receptor_sensitivity"
    
    # Custom types
    CUSTOM = "custom"
    
    def __str__(self) -> str:
        """String representation of the prediction type."""
        return self.value
    
    @property
    def category(self) -> PredictionCategory:
        """Get the category this prediction type belongs to."""
        if self.name.endswith('_RISK'):
            return PredictionCategory.RISK
        elif self.name.endswith('_RESPONSE') or 'TREATMENT' in self.name:
            return PredictionCategory.TREATMENT
        elif 'SYMPTOM' in self.name:
            return PredictionCategory.SYMPTOM
        elif 'OUTCOME' in self.name or 'RECOVERY' in self.name or 'QUALITY' in self.name:
            return PredictionCategory.OUTCOME
        elif any(term in self.name for term in ['NEUROTRANSMITTER', 'BRAIN', 'RECEPTOR']):
            return PredictionCategory.DIGITAL_TWIN
        else:
            return PredictionCategory.CUSTOM
