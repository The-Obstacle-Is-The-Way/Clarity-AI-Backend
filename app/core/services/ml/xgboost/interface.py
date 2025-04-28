"""
Interface definition for the XGBoost service.

This module defines the abstract base class, enums, and observer pattern
for the XGBoost service.
"""

import abc
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Dict, List, Any, Optional, Set, Union


class ModelType(str, Enum):
    """Types of XGBoost models available in the service."""
    
    RISK = "risk"
    RISK_RELAPSE = "risk_relapse"
    RISK_SUICIDE = "risk_suicide"
    RISK_HOSPITALIZATION = "risk_hospitalization"
    # Generic alias for medication treatment response (used in tests)
    TREATMENT_RESPONSE_MEDICATION = "treatment_response_medication"
    TREATMENT_MEDICATION_SSRI = "medication_ssri-response"
    TREATMENT_MEDICATION_SNRI = "medication_snri-response"
    TREATMENT_MEDICATION_ATYPICAL = "medication_atypical-response"
    TREATMENT_THERAPY_CBT = "therapy_cbt-response"
    TREATMENT_THERAPY_DBT = "therapy_dbt-response"
    TREATMENT_THERAPY_IPT = "therapy_ipt-response"
    TREATMENT_THERAPY_PSYCHODYNAMIC = "therapy_psychodynamic-response"
    OUTCOME_SYMPTOM = "symptom-outcome"
    OUTCOME_FUNCTIONAL = "functional-outcome"
    OUTCOME_QUALITY_OF_LIFE = "quality_of_life-outcome"


class EventType(str, Enum):
    """Types of events emitted by the XGBoost service."""
    
    INITIALIZATION = "initialization"
    PREDICTION = "prediction"
    INTEGRATION = "integration"
    ERROR = "error"


class PrivacyLevel(Enum):
    """Privacy level for PHI detection and handling."""
    
    STANDARD = 1  # Basic PHI detection (SSNs, MRNs, names)
    ENHANCED = 2  # Enhanced detection (includes contact info)
    MAXIMUM = 3   # Maximum detection (includes demographic info)
    STRICT = 4    # Strictest detection (legacy/test compatibility)


class Observer(ABC):
    """Observer interface for the Observer pattern."""
    
    @abstractmethod
    def update(self, event_type: EventType, data: Dict[str, Any]) -> None:
        """
        Receive an update from the observed subject.
        
        Args:
            event_type: Type of event
            data: Event data
        """
        pass


class XGBoostInterface(ABC):
    """
    Abstract interface for the XGBoost service.
    
    This interface defines the contract that all XGBoost service
    implementations must follow.
    """
    
    def __init__(self):
        """Initialize a new XGBoost service interface."""
        self._initialized = False
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the XGBoost service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        pass
    
    @abstractmethod
    async def register_observer(self, event_type: Union[EventType, str], observer: Observer) -> None:
        """
        Register an observer for a specific event type.
        
        Args:
            event_type: Type of event to observe, or "*" for all events
            observer: Observer to register
        """
        pass
    
    @abstractmethod
    async def unregister_observer(self, event_type: Union[EventType, str], observer: Observer) -> None:
        """
        Unregister an observer for a specific event type.
        
        Args:
            event_type: Type of event to stop observing
            observer: Observer to unregister
        """
        pass
    
    @abstractmethod
    async def predict_risk(
        self,
        patient_id: str,
        risk_type: str,
        clinical_data: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Predict risk level using a risk model.
        
        Args:
            patient_id: Patient identifier
            risk_type: Type of risk to predict
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters
            
        Returns:
            Risk prediction result
            
        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
        """
        pass
    
    @abstractmethod
    async def predict_treatment_response(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: Dict[str, Any],
        clinical_data: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Predict response to a psychiatric treatment.
        
        Args:
            patient_id: Patient identifier
            treatment_type: Type of treatment (e.g., medication_ssri)
            treatment_details: Treatment details
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters
            
        Returns:
            Treatment response prediction result
            
        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
        """
        pass
    
    @abstractmethod
    async def predict_outcome(
        self,
        patient_id: str,
        outcome_timeframe: Dict[str, int],
        clinical_data: Dict[str, Any],
        treatment_plan: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Predict clinical outcomes based on treatment plan.
        
        Args:
            patient_id: Patient identifier
            outcome_timeframe: Timeframe for outcome prediction
            clinical_data: Clinical data for prediction
            treatment_plan: Treatment plan details
            **kwargs: Additional prediction parameters
            
        Returns:
            Outcome prediction result
            
        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
        """
        pass
    
    @abstractmethod
    async def get_feature_importance(
        self,
        patient_id: str,
        model_type: str,
        prediction_id: str
    ) -> Dict[str, Any]:
        """
        Get feature importance for a prediction.
        
        Args:
            patient_id: Patient identifier
            model_type: Type of model
            prediction_id: Prediction identifier
            
        Returns:
            Feature importance data
            
        Raises:
            ResourceNotFoundError: If prediction not found
            ValidationError: If parameters are invalid
        """
        pass
    
    @abstractmethod
    async def integrate_with_digital_twin(
        self,
        patient_id: str,
        profile_id: str,
        prediction_id: str
    ) -> Dict[str, Any]:
        """
        Integrate prediction with digital twin profile.
        
        Args:
            patient_id: Patient identifier
            profile_id: Digital twin profile identifier
            prediction_id: Prediction identifier
            
        Returns:
            Integration result
            
        Raises:
            ResourceNotFoundError: If prediction not found
            ValidationError: If parameters are invalid
        """
        pass
    
    @abstractmethod
    async def get_model_info(self, model_type: str) -> Dict[str, Any]:
        """
        Get information about a model.
        
        Args:
            model_type: Type of model
            
        Returns:
            Model information
            
        Raises:
            ResourceNotFoundError: If model not found
            ValidationError: If parameters are invalid
        """
        pass
    
    @abstractmethod
    async def get_available_models(self) -> List[Dict[str, Any]]:
        """
        Get a list of available models.

        Returns:
            List of available models with basic info
        """
        pass
    
    def _ensure_initialized(self) -> None:
        """
        Ensure the service is initialized before use.
        
        Raises:
            ConfigurationError: If service is not initialized
        """
        if not self._initialized:
            from app.core.services.ml.xgboost.exceptions import ConfigurationError
            raise ConfigurationError(
                "XGBoost service not initialized. Call initialize() first."
            )

    @property
    @abstractmethod
    def is_initialized(self) -> bool:
        """Check if the service is initialized."""
        pass