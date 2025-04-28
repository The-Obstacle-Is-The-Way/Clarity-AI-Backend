"""
Domain interfaces for ML services in the NOVAMIND system.

This module defines the domain interfaces for ML services used in the Digital Twin
functionality, following Clean Architecture principles by ensuring that the domain
layer has no dependencies on infrastructure implementations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID


class ISymptomForecastingService(ABC):
    """
    Interface for the Symptom Forecasting Service.

    This interface defines the contract that any implementation of the
    Symptom Forecasting Service must fulfill, allowing the domain layer
    to interact with the service without depending on its implementation.
    """

    @abstractmethod
    async def forecast_symptoms(
        self,
        patient_id: UUID,
        data: dict[str, Any],
        horizon: int = 14,
        use_ensemble: bool = True,
    ) -> dict[str, Any]:
        """
        Generate symptom forecasts for a patient.

        Args:
            patient_id: UUID of the patient
            data: Patient data including symptom history
            horizon: Forecast horizon in days
            use_ensemble: Whether to use ensemble of models

        Returns:
            Dictionary containing forecast results

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the model fails to generate predictions
        """
        pass

    @abstractmethod
    async def analyze_symptom_patterns(
        self, patient_id: UUID, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Analyze patterns in symptom history.

        Args:
            patient_id: UUID of the patient
            data: Patient data including symptom history

        Returns:
            Dictionary containing pattern analysis results

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the analysis fails
        """
        pass

    @abstractmethod
    async def identify_risk_periods(
        self, patient_id: UUID, forecast: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Identify periods of elevated risk based on symptom forecasts.

        Args:
            patient_id: UUID of the patient
            forecast: Symptom forecast data

        Returns:
            Dictionary containing identified risk periods

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the analysis fails
        """
        pass

    @abstractmethod
    async def get_model_performance_metrics(self) -> dict[str, Any]:
        """
        Get performance metrics for the symptom forecasting models.

        Returns:
            Dictionary containing model performance metrics

        Raises:
            ModelInferenceError: If the metrics cannot be retrieved
        """
        pass


class IBiometricCorrelationService(ABC):
    """
    Interface for the Biometric Correlation Service.

    This interface defines the contract that any implementation of the
    Biometric Correlation Service must fulfill, allowing the domain layer
    to interact with the service without depending on its implementation.
    """

    @abstractmethod
    async def analyze_correlations(
        self,
        patient_id: UUID,
        biometric_data: list[dict[str, Any]],
        mental_health_indicators: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Analyze correlations between biometric data and mental health indicators.

        Args:
            patient_id: UUID of the patient
            biometric_data: Time series of biometric measurements
            mental_health_indicators: Time series of mental health indicators

        Returns:
            Dictionary containing correlation analysis results

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the analysis fails
        """
        pass

    @abstractmethod
    async def detect_anomalies(
        self,
        patient_id: UUID,
        biometric_data: list[dict[str, Any]],
        sensitivity: str = "medium",
    ) -> dict[str, Any]:
        """
        Detect anomalies in biometric data.

        Args:
            patient_id: UUID of the patient
            biometric_data: Time series of biometric measurements
            sensitivity: Detection sensitivity level ("low", "medium", "high")

        Returns:
            Dictionary containing detected anomalies

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the detection fails
        """
        pass

    @abstractmethod
    async def generate_monitoring_plan(
        self, patient_id: UUID, correlation_results: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Generate a personalized monitoring plan based on correlation analysis.

        Args:
            patient_id: UUID of the patient
            correlation_results: Results from correlation analysis

        Returns:
            Dictionary containing monitoring plan

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the plan generation fails
        """
        pass

    @abstractmethod
    async def analyze_lag_relationships(
        self,
        patient_id: UUID,
        biometric_data: list[dict[str, Any]],
        mental_health_indicators: list[dict[str, Any]],
        max_lag: int = 7,
    ) -> dict[str, Any]:
        """
        Analyze lagged relationships between biometric data and mental health.

        Args:
            patient_id: UUID of the patient
            biometric_data: Time series of biometric measurements
            mental_health_indicators: Time series of mental health indicators
            max_lag: Maximum lag in days to analyze

        Returns:
            Dictionary containing lag analysis results

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the analysis fails
        """
        pass


class IPharmacogenomicsService(ABC):
    """
    Interface for the Pharmacogenomics Service.

    This interface defines the contract that any implementation of the
    Pharmacogenomics Service must fulfill, allowing the domain layer
    to interact with the service without depending on its implementation.
    """

    @abstractmethod
    async def predict_medication_responses(
        self,
        patient_id: UUID,
        patient_data: dict[str, Any],
        medications: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Predict patient responses to psychiatric medications.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            medications: Optional list of medications to predict (defaults to all)

        Returns:
            Dictionary containing prediction results

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the prediction fails
        """
        pass

    @abstractmethod
    async def analyze_gene_medication_interactions(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Analyze interactions between patient's genetic markers and medications.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers

        Returns:
            Dictionary containing interaction analysis

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the analysis fails
        """
        pass

    @abstractmethod
    async def generate_treatment_recommendations(
        self,
        patient_id: UUID,
        prediction_results: dict[str, Any],
        patient_history: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Generate personalized treatment recommendations based on predictions.

        Args:
            patient_id: UUID of the patient
            prediction_results: Results from medication response prediction
            patient_history: Optional patient treatment history

        Returns:
            Dictionary containing treatment recommendations

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the recommendation generation fails
        """
        pass

    @abstractmethod
    async def predict_side_effect_risks(
        self, patient_id: UUID, patient_data: dict[str, Any], medications: list[str]
    ) -> dict[str, Any]:
        """
        Predict risk of side effects for specific medications.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            medications: List of medications to analyze

        Returns:
            Dictionary containing side effect risk predictions

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the prediction fails
        """
        pass


class IDigitalTwinIntegrationService(ABC):
    """
    Interface for the Digital Twin Integration Service.

    This interface defines the contract that any implementation of the
    Digital Twin Integration Service must fulfill, allowing the domain layer
    to interact with the service without depending on its implementation.
    """

    @abstractmethod
    async def generate_comprehensive_patient_insights(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Generate comprehensive patient insights by coordinating all microservices.

        Args:
            patient_id: UUID of the patient
            patient_data: Comprehensive patient data

        Returns:
            Dictionary containing integrated insights from all microservices

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If any service fails
        """
        pass

    @abstractmethod
    async def get_digital_twin_status(self, patient_id: UUID) -> dict[str, Any]:
        """
        Get the status of the Digital Twin for a specific patient.

        Args:
            patient_id: UUID of the patient

        Returns:
            Dictionary containing Digital Twin status

        Raises:
            ValidationError: If the patient ID is invalid
            ModelInferenceError: If the status cannot be retrieved
        """
        pass

    @abstractmethod
    async def update_digital_twin(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Update the Digital Twin with new patient data.

        Args:
            patient_id: UUID of the patient
            patient_data: New patient data

        Returns:
            Dictionary containing update status

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the update fails
        """
        pass

    @abstractmethod
    async def get_historical_insights(
        self, patient_id: UUID, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """
        Get historical insights for a specific time period.

        Args:
            patient_id: UUID of the patient
            start_date: Start date for historical insights
            end_date: End date for historical insights

        Returns:
            Dictionary containing historical insights

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the retrieval fails
        """
        pass
