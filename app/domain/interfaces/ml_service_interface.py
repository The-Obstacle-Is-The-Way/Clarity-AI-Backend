"""
Interface for Machine Learning Services.

Defines the contract for various ML model services used within the application,
ensuring a consistent interaction pattern regardless of the underlying model
or implementation (e.g., XGBoost, MentaLLaMA, PAT).
"""
from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class MLServiceInterface(ABC):
    """Abstract base class for ML services."""

    @abstractmethod
    async def predict(
        self, patient_id: UUID, features: dict[str, Any], model_type: str, **kwargs
    ) -> dict[str, Any]:
        """Generic prediction method."""
        pass

    @abstractmethod
    async def get_model_info(self, model_type: str) -> dict[str, Any]:
        """Get information about a specific model type."""
        pass

    @abstractmethod
    async def healthcheck(self) -> dict[str, Any]:
        """Check the health status of the ML service."""
        pass

    # Add other common ML operations as needed, e.g.,
    # - get_feature_importance
    # - analyze_text (for NLP models)


class BiometricCorrelationInterface(ABC):
    """Interface for the Biometric Correlation service."""

    @abstractmethod
    async def analyze_correlations(
        self,
        patient_id: UUID,
        biometric_data: list[dict[str, Any]],
        mental_health_indicators: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze correlations between biometric data and mental health indicators."""
        pass


class DigitalTwinServiceInterface(ABC):
    """Interface for the Digital Twin integration service."""

    @abstractmethod
    async def generate_comprehensive_patient_insights(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate comprehensive insights for a patient."""
        pass

    @abstractmethod
    async def update_digital_twin(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a patient's Digital Twin with new data."""
        pass

    @abstractmethod
    async def get_digital_twin_status(self, patient_id: UUID) -> dict[str, Any]:
        """Get the status of a patient's Digital Twin."""
        pass


class PharmacogenomicsInterface(ABC):
    """Interface for the Pharmacogenomics service."""

    @abstractmethod
    async def predict_medication_responses(
        self,
        patient_id: UUID,
        patient_data: dict[str, Any],
        medications: list[str] | None = None,
    ) -> dict[str, Any]:
        """Predict patient responses to psychiatric medications."""
        pass

    @abstractmethod
    async def recommend_treatment_plan(
        self,
        patient_id: UUID,
        patient_data: dict[str, Any],
        diagnosis: str,
        current_medications: list[str],
    ) -> dict[str, Any]:
        """Recommend a treatment plan based on pharmacogenomic data."""
        pass


class SymptomForecastingInterface(ABC):
    """Interface for the Symptom Forecasting service."""

    @abstractmethod
    async def forecast_symptoms(
        self,
        patient_id: UUID,
        symptom_history: list[dict[str, Any]],
        forecast_days: int,
    ) -> dict[str, Any]:
        """Forecast patient symptoms based on historical data."""
        pass
