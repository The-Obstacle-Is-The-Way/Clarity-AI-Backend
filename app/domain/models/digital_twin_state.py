"""
Digital Twin State Enumeration.

This module defines the possible states of a digital twin model in the system.
"""

from enum import Enum, auto


class DigitalTwinState(Enum):
    """
    Enumeration of possible states for a Digital Twin model.
    
    These states represent the lifecycle stages of a digital twin from
    creation through training, validation, and deployment.
    """
    
    # Initial state when the twin is first created but not yet trained
    INITIALIZED = auto()
    
    # Training is in progress
    TRAINING = auto()
    
    # Model has been trained but not yet validated
    TRAINED = auto()
    
    # Validation of the model is in progress
    VALIDATING = auto()
    
    # Model has been validated and is ready for use
    VALIDATED = auto()
    
    # Model is actively being used for predictions
    ACTIVE = auto()
    
    # Model is temporarily disabled but can be reactivated
    DISABLED = auto()
    
    # Model has been archived and should not be used for new predictions
    ARCHIVED = auto()
    
    # Model has failed validation and needs retraining
    FAILED = auto()
    
    # Model is scheduled for retraining with new data
    RETRAINING = auto()
    
    # Model has been deprecated and should be replaced
    DEPRECATED = auto()
