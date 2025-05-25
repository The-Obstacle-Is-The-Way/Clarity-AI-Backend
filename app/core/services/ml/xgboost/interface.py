"""
XGBoost ML Service Interface.
"""

import abc
from enum import Enum
from typing import Any

from pydantic import BaseModel

# Import the constants
from app.core.services.ml.xgboost.constants import ModelType
from app.domain.interfaces.ml_service_interface import MLServiceInterface

# Explicit exports for proper module interface
__all__ = [
    "XGBoostInterface",
    "ModelType",
    "ModelMetadata",
    "EventType",
    "Observer",
    "PrivacyLevel"
]


class XGBoostInterface(MLServiceInterface):
    """Interface for XGBoost ML Service implementation."""

    @abc.abstractmethod
    async def predict_risk(
        self,
        patient_id: str,
        risk_type: str,
        clinical_data: dict[str, Any],
        time_frame_days: int | None = None,
    ) -> dict[str, Any]:
        """
        Predict patient risk based on clinical data.

        Args:
            patient_id: Unique identifier for the patient
            risk_type: Type of risk to predict (e.g., relapse, suicide)
            clinical_data: Clinical data for prediction
            time_frame_days: Time frame in days for the prediction

        Returns:
            Dictionary containing risk prediction results
        """
        pass

    @abc.abstractmethod
    async def predict_treatment_response(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: dict[str, Any],
        clinical_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Predict patient response to treatment.

        Args:
            patient_id: Unique identifier for the patient
            treatment_type: Type of treatment (e.g., medication, therapy)
            treatment_details: Details of the treatment
            clinical_data: Clinical data for prediction

        Returns:
            Dictionary containing treatment response prediction
        """
        pass

    @abc.abstractmethod
    async def predict_outcome(
        self,
        patient_id: str,
        outcome_timeframe: dict[str, Any],
        clinical_data: dict[str, Any],
        treatment_plan: dict[str, Any],
        social_determinants: dict[str, Any] | None = None,
        comorbidities: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Predict patient outcome based on clinical data and treatment plan.

        Args:
            patient_id: Unique identifier for the patient
            outcome_timeframe: Timeframe for outcome prediction
            clinical_data: Clinical data for prediction
            treatment_plan: Treatment plan details
            social_determinants: Social determinants of health
            comorbidities: Comorbid conditions

        Returns:
            Dictionary containing outcome prediction results
        """
        pass

    @abc.abstractmethod
    async def get_model_info(self, model_type: str | ModelType) -> dict[str, Any]:
        """
        Get information about an XGBoost model.

        Args:
            model_type: Type of model to get info for

        Returns:
            Dictionary containing model metadata and capabilities
        """
        pass

    @abc.abstractmethod
    async def get_feature_importance(
        self,
        model_type: str | ModelType,
        prediction_id: str,
        patient_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Get feature importance for a prediction.

        Args:
            model_type: Type of model used for prediction
            prediction_id: ID of the prediction
            patient_id: Optional patient ID for authorization

        Returns:
            Dictionary containing feature importance data
        """
        pass

    @abc.abstractmethod
    async def integrate_with_digital_twin(
        self,
        patient_id: str,
        profile_id: str,
        prediction_id: str,
        additional_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Integrate a prediction with a digital twin.

        Args:
            patient_id: ID of the patient
            profile_id: ID of the digital twin profile
            prediction_id: ID of the prediction to integrate
            additional_data: Optional additional data for integration

        Returns:
            Dictionary containing integration results
        """
        pass

    @abc.abstractmethod
    async def healthcheck(self) -> dict[str, Any]:
        """
        Check health status of XGBoost service.

        Returns:
            Dictionary containing service health status and dependencies
        """
        pass


class ModelMetadata(BaseModel):
    """Metadata structure for XGBoost models."""

    name: str
    version: str
    description: str
    input_features: list[str]
    output_types: list[str]
    performance_metrics: dict[str, float]


# Dummy definitions to satisfy imports elsewhere
class EventType(str, Enum):
    INITIALIZATION = "initialization"
    PREDICTION_START = "prediction_start"
    PREDICTION_COMPLETE = "prediction_complete"
    ERROR = "error"


class Observer:
    async def update(self, event_type: EventType, data: dict[str, Any]) -> None:
        pass


class PrivacyLevel(str, Enum):
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"
    STRICT = "strict"  # Added for test compatibility
