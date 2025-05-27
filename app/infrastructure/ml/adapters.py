"""
Adapters for ML Services in NOVAMIND.

This module implements adapter classes that connect the infrastructure ML services
to the domain interfaces, following Clean Architecture principles and ensuring
proper separation of concerns.
"""

import logging
from typing import Any
from uuid import UUID

from app.domain.interfaces.ml_service_interface import (
    BiometricCorrelationInterface,
    DigitalTwinServiceInterface,
    PharmacogenomicsInterface,
    SymptomForecastingInterface,
)
from app.infrastructure.ml.biometric_correlation.model_service import (
    BiometricCorrelationService,
)
from app.infrastructure.ml.digital_twin_integration_service import (
    DigitalTwinIntegrationService,
)
from app.infrastructure.ml.pharmacogenomics.model_service import PharmacogenomicsService
from app.infrastructure.ml.symptom_forecasting.model_service import (
    SymptomForecastingService,
)


class SymptomForecastingAdapter(SymptomForecastingInterface):
    """
    Adapter for the Symptom Forecasting Service.

    This adapter implements the SymptomForecastingInterface and delegates
    calls to the infrastructure SymptomForecastingService.
    """

    def __init__(self, service: SymptomForecastingService) -> None:
        """
        Initialize the adapter.

        Args:
            service: The infrastructure service to delegate to
        """
        self._service = service
        logging.info("SymptomForecastingAdapter initialized")

    async def forecast_symptoms(
        self,
        patient_id: UUID,
        symptom_history: list[dict[str, Any]],
        forecast_days: int = 30,
    ) -> dict[str, Any]:
        """
        Forecast patient symptoms based on historical data.

        Args:
            patient_id: UUID of the patient
            symptom_history: List of historical symptom records
            forecast_days: Number of days to forecast

        Returns:
            Dictionary containing forecast results
        """
        return await self._service.forecast_symptoms(
            patient_id=patient_id,
            symptom_history=symptom_history,
            forecast_days=forecast_days,
        )

    async def detect_symptom_patterns(
        self, patient_id: UUID, symptom_history: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Detect patterns in patient symptom history.

        Args:
            patient_id: UUID of the patient
            symptom_history: List of historical symptom records

        Returns:
            Dictionary containing pattern detection results
        """
        return await self._service.detect_patterns(
            patient_id=patient_id, symptom_history=symptom_history
        )

    async def get_model_status(self, patient_id: UUID) -> dict[str, Any]:
        """
        Get the status of a patient's symptom forecasting model.

        Args:
            patient_id: UUID of the patient

        Returns:
            Dictionary containing model status
        """
        return await self._service.get_model_status(patient_id)


class BiometricCorrelationAdapter(BiometricCorrelationInterface):
    """
    Adapter for the Biometric Correlation Service.

    This adapter implements the BiometricCorrelationInterface and delegates
    calls to the infrastructure BiometricCorrelationService.
    """

    def __init__(self, service: BiometricCorrelationService):
        """
        Initialize the adapter.

        Args:
            service: The infrastructure service to delegate to
        """
        self._service = service
        logging.info("BiometricCorrelationAdapter initialized")

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
            biometric_data: List of biometric data records
            mental_health_indicators: List of mental health indicator records

        Returns:
            Dictionary containing correlation analysis results
        """
        return await self._service.analyze_correlations(
            patient_id=patient_id,
            biometric_data=biometric_data,
            mental_health_indicators=mental_health_indicators,
        )

    async def detect_anomalies(
        self,
        patient_id: UUID,
        biometric_data: list[dict[str, Any]],
        mental_health_indicators: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Detect anomalies in biometric data and mental health indicators.

        Args:
            patient_id: UUID of the patient
            biometric_data: List of biometric data records
            mental_health_indicators: List of mental health indicator records

        Returns:
            Dictionary containing anomaly detection results
        """
        return await self._service.detect_anomalies(
            patient_id=patient_id,
            biometric_data=biometric_data,
            mental_health_indicators=mental_health_indicators,
        )

    async def get_model_status(self, patient_id: UUID) -> dict[str, Any]:
        """
        Get the status of a patient's biometric correlation model.

        Args:
            patient_id: UUID of the patient

        Returns:
            Dictionary containing model status
        """
        return await self._service.get_model_status(patient_id)


class PharmacogenomicsAdapter(PharmacogenomicsInterface):
    """
    Adapter for the Pharmacogenomics Service.

    This adapter implements the PharmacogenomicsInterface and delegates
    calls to the infrastructure PharmacogenomicsService.
    """

    def __init__(self, service: PharmacogenomicsService):
        """
        Initialize the adapter.

        Args:
            service: The infrastructure service to delegate to
        """
        self._service = service
        logging.info("PharmacogenomicsAdapter initialized")

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
        """
        return await self._service.predict_medication_responses(
            patient_id=patient_id, patient_data=patient_data, medications=medications
        )

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
        """
        return await self._service.analyze_gene_medication_interactions(
            patient_id=patient_id, patient_data=patient_data
        )

    async def predict_side_effects(
        self, patient_id: UUID, patient_data: dict[str, Any], medications: list[str]
    ) -> dict[str, Any]:
        """
        Predict potential side effects for specified medications.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            medications: List of medications to predict side effects for

        Returns:
            Dictionary containing side effect predictions
        """
        return await self._service.predict_side_effects(
            patient_id=patient_id, patient_data=patient_data, medications=medications
        )

    async def recommend_treatment_plan(
        self,
        patient_id: UUID,
        patient_data: dict[str, Any],
        diagnosis: str,
        current_medications: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Recommend a personalized treatment plan based on genetic markers and diagnosis.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            diagnosis: Patient diagnosis
            current_medications: Optional list of current medications

        Returns:
            Dictionary containing treatment recommendations
        """
        return await self._service.recommend_treatment_plan(
            patient_id=patient_id,
            patient_data=patient_data,
            diagnosis=diagnosis,
            current_medications=current_medications,
        )


class DigitalTwinServiceAdapter(DigitalTwinServiceInterface):
    """
    Adapter for the Digital Twin Integration Service.

    This adapter implements the DigitalTwinServiceInterface and delegates
    calls to the infrastructure DigitalTwinIntegrationService.
    """

    def __init__(self, service: DigitalTwinIntegrationService):
        """
        Initialize the adapter.

        Args:
            service: The infrastructure service to delegate to
        """
        self._service = service
        logging.info("DigitalTwinServiceAdapter initialized")

    async def generate_comprehensive_patient_insights(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Generate comprehensive insights for a patient using all ML services.

        Args:
            patient_id: UUID of the patient
            patient_data: Comprehensive patient data

        Returns:
            Dictionary containing comprehensive insights
        """
        return await self._service.generate_comprehensive_patient_insights(
            patient_id=patient_id, patient_data=patient_data
        )

    async def update_digital_twin(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Update the Digital Twin with new patient data.

        Args:
            patient_id: UUID of the patient
            patient_data: New patient data

        Returns:
            Dictionary containing update results
        """
        return await self._service.update_digital_twin(
            patient_id=patient_id, patient_data=patient_data
        )

    async def get_digital_twin_status(self, patient_id: UUID) -> dict[str, Any]:
        """
        Get the status of a patient's Digital Twin.

        Args:
            patient_id: UUID of the patient

        Returns:
            Dictionary containing Digital Twin status
        """
        return await self._service.get_digital_twin_status(patient_id)
