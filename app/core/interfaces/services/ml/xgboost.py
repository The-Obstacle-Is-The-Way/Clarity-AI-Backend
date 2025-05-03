"""
Core domain interfaces for XGBoost ML services.

This module defines the interface contracts for XGBoost-based ML services,
following clean architecture principles and the dependency inversion principle.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

from app.core.enums.privacy_level import PrivacyLevel


class XGBoostInterface(ABC):
    """
    Interface for XGBoost-based ML services following clean architecture.
    
    This enforces a consistent contract for all XGBoost implementations,
    whether they're using local models, AWS SageMaker, or other providers.
    """
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the XGBoost service with configuration.
        
        Args:
            config: Configuration dictionary
        """
        pass
    
    @abstractmethod
    def is_initialized(self) -> bool:
        """
        Check if the service is properly initialized.
        
        Returns:
            True if initialized, False otherwise
        """
        pass
    
    @abstractmethod
    def predict(self, patient_id: str, features: Dict[str, Any], model_type: str, **kwargs) -> Dict[str, Any]:
        """
        Generic prediction method required for all ML services.
        
        Args:
            patient_id: ID of the patient
            features: Dictionary of features for prediction
            model_type: Type of model to use for prediction
            **kwargs: Additional arguments for prediction
            
        Returns:
            Dictionary with prediction results
        """
        pass
    
    @abstractmethod
    def predict_risk(
        self,
        patient_id: str,
        risk_type: str,
        features: Optional[Dict[str, Any]] = None,
        clinical_data: Optional[Dict[str, Any]] = None,
        time_frame_days: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Predict risk level using a risk model.
        
        Args:
            patient_id: Patient identifier
            risk_type: Type of risk to predict
            features: Feature values for prediction (optional)
            clinical_data: Clinical data for prediction (optional)
            time_frame_days: Timeframe for risk prediction in days (optional)
            **kwargs: Additional prediction parameters
            
        Returns:
            Risk prediction result
        """
        pass
    
    @abstractmethod
    def predict_treatment_response(
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
            treatment_type: Type of treatment
            treatment_details: Treatment details
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters
            
        Returns:
            Treatment response prediction result
        """
        pass
    
    @abstractmethod
    def predict_outcome(
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
        """
        pass
    
    @abstractmethod
    def get_feature_importance(
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
        """
        pass
    
    @abstractmethod
    def get_available_models(self) -> List[Dict[str, Any]]:
        """
        Get a list of available models.
        
        Returns:
            List of model information dictionaries
        """
        pass
    
    @abstractmethod
    def get_model_info(self, model_type: str) -> Dict[str, Any]:
        """
        Get information about a model.
        
        Args:
            model_type: Type of model
            
        Returns:
            Model information
        """
        pass


class AWSServiceFactoryInterface(ABC):
    """
    Interface for AWS service factory.
    
    This abstracts AWS service creation to facilitate testing and DI.
    """
    
    @abstractmethod
    def create_sagemaker_runtime(self) -> Any:
        """Create SageMaker runtime client."""
        pass
    
    @abstractmethod
    def create_sagemaker(self) -> Any:
        """Create SageMaker client."""
        pass
    
    @abstractmethod
    def create_s3(self) -> Any:
        """Create S3 client."""
        pass
    
    @abstractmethod
    def create_dynamodb(self) -> Any:
        """Create DynamoDB client."""
        pass
