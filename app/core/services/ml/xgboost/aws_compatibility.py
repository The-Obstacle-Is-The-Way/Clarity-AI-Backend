"""
Compatibility module to provide backward compatibility during transition.

This module maintains the same interface as the original aws.py but delegates
all functionality to the definitive aws_service.py implementation.
"""

import logging
from typing import Any

from app.core.services.ml.xgboost.aws_service import AWSXGBoostService
from app.core.services.ml.xgboost.interface import EventType, Observer, XGBoostInterface
from app.infrastructure.aws.service_factory_provider import get_aws_service_factory

logger = logging.getLogger(__name__)

# Create a singleton instance of the definitive implementation
_canonical_instance = None


def get_service_instance() -> AWSXGBoostService:
    """Get or create the definitive XGBoost service instance."""
    global _canonical_instance
    if _canonical_instance is None:
        aws_factory = get_aws_service_factory()
        _canonical_instance = AWSXGBoostService(aws_service_factory=aws_factory)
    return _canonical_instance


class AWSXGBoostService(XGBoostInterface):
    """
    Compatibility implementation that delegates to the definitive AWS XGBoost service.
    
    This compatibility layer maintains backward compatibility with existing code that
    imports from the original aws.py, while delegating all functionality
    to the definitive implementation.
    """

    def __init__(self):
        """Initialize the compatibility layer to use the definitive implementation."""
        super().__init__()
        
    async def predict(self, patient_id: str, features: dict[str, Any], model_type: str, **kwargs) -> dict[str, Any]:
        """Generic prediction method required by MLServiceInterface.
        
        Args:
            patient_id: ID of the patient
            features: Dictionary of features for prediction
            model_type: Type of model to use for prediction
            **kwargs: Additional arguments for prediction
            
        Returns:
            Dictionary with prediction results
        """
        # Delegate to the canonical implementation
        return await get_service_instance().predict(patient_id, features, model_type, **kwargs)
        self._impl = get_service_instance()
        self._initialized = self._impl.is_initialized
        logger.info("AWS XGBoost compatibility layer initialized, using definitive implementation")

    @property
    def is_initialized(self) -> bool:
        """Check if the service is initialized."""
        return self._impl.is_initialized

    async def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the XGBoost service with configuration.
        
        Args:
            config: Configuration dictionary
        """
        await self._impl.initialize(config)
        self._initialized = self._impl.is_initialized

    async def predict_risk(
        self,
        patient_id: str,
        risk_type: str,
        clinical_data: dict[str, Any],
        **kwargs
    ) -> dict[str, Any]:
        """
        Predict risk level using a risk model.
        
        Args:
            patient_id: Patient identifier
            risk_type: Type of risk to predict
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters
            
        Returns:
            Risk prediction result
        """
        return await self._impl.predict_risk(
            patient_id=patient_id,
            risk_type=risk_type,
            clinical_data=clinical_data,
            **kwargs
        )

    async def predict_treatment_response(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: dict[str, Any],
        clinical_data: dict[str, Any],
        **kwargs
    ) -> dict[str, Any]:
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
        """
        return await self._impl.predict_treatment_response(
            patient_id=patient_id,
            treatment_type=treatment_type,
            treatment_details=treatment_details,
            clinical_data=clinical_data,
            **kwargs
        )

    async def predict_outcome(
        self,
        patient_id: str,
        outcome_timeframe: dict[str, int],
        clinical_data: dict[str, Any],
        treatment_plan: dict[str, Any],
        **kwargs
    ) -> dict[str, Any]:
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
        return await self._impl.predict_outcome(
            patient_id=patient_id,
            outcome_timeframe=outcome_timeframe,
            clinical_data=clinical_data,
            treatment_plan=treatment_plan,
            **kwargs
        )

    async def get_feature_importance(
        self,
        model_type: str,
        patient_id: str | None = None,
        **kwargs
    ) -> dict[str, Any]:
        """
        Get feature importance for a specific model type.
        
        Args:
            model_type: Type of model
            patient_id: Optional patient ID for personalized feature importance
            **kwargs: Additional parameters
            
        Returns:
            Dictionary of features and their importance scores
        """
        return await self._impl.get_feature_importance(
            model_type=model_type,
            patient_id=patient_id,
            **kwargs
        )

    async def get_prediction(self, prediction_id: str) -> dict[str, Any]:
        """
        Get a stored prediction by ID.
        
        Args:
            prediction_id: Unique identifier for the prediction
            
        Returns:
            Stored prediction details
        """
        return await self._impl.get_prediction(prediction_id)

    async def get_available_models(self) -> list[dict[str, Any]]:
        """
        Get list of available XGBoost models.
        
        Returns:
            List of model information dictionaries
        """
        return await self._impl.get_available_models()

    async def get_model_info(self, model_type: str) -> dict[str, Any]:
        """
        Get information about a specific model.
        
        Args:
            model_type: Type of model/risk
            
        Returns:
            Model information dictionary
        """
        return await self._impl.get_model_info(model_type)

    async def healthcheck(self) -> dict[str, Any]:
        """
        Perform a health check of the XGBoost service.
        
        Returns:
            Health check results with status (HEALTHY, DEGRADED, UNHEALTHY)
        """
        return await self._impl.healthcheck()

    async def integrate_with_digital_twin(self, patient_id: str, profile_id: str, prediction_id: str) -> dict[str, Any]:
        """
        Integrate XGBoost predictions with a patient's digital twin.
        
        Args:
            patient_id: Patient identifier
            profile_id: Digital twin profile identifier
            prediction_id: Prediction identifier to integrate
            
        Returns:
            Integration status and details
        """
        return await self._impl.integrate_with_digital_twin(
            patient_id=patient_id,
            profile_id=profile_id,
            prediction_id=prediction_id
        )

    async def register_observer(self, event_type: EventType | str, observer: Observer) -> None:
        """
        Register an observer for a specific event type.
        
        Args:
            event_type: Type of event to observe, or "*" for all events
            observer: Observer to register
        """
        await self._canonical.register_observer(event_type, observer)

    async def unregister_observer(self, event_type: EventType | str, observer: Observer) -> None:
        """
        Unregister an observer for a specific event type.
        
        Args:
            event_type: Type of event to stop observing
            observer: Observer to unregister
        """
        await self._canonical.unregister_observer(event_type, observer)
