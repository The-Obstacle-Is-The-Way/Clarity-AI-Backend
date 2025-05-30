"""
Extended interface for Digital Twin Integration Service.

This module defines an extended interface that includes additional methods
beyond the core IDigitalTwinIntegrationService interface.
"""

from abc import abstractmethod
from typing import Any
from uuid import UUID

from app.domain.interfaces.ml_services import IDigitalTwinIntegrationService


class IExtendedDigitalTwinIntegrationService(IDigitalTwinIntegrationService):
    """
    Extended interface for the Digital Twin Integration Service.

    This interface extends the core IDigitalTwinIntegrationService with additional
    methods for creating, retrieving, and simulating digital twins.
    """

    @abstractmethod
    async def create_digital_twin(
        self,
        patient_id: UUID,
        initial_data: dict[str, Any] | None = None,
        model_configuration: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new digital twin for a patient.

        Args:
            patient_id: Patient identifier
            initial_data: Optional initialization data
            model_configuration: Optional configuration for the Digital Twin models

        Returns:
            Dictionary containing creation status and digital twin ID if successful

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the creation fails
        """
        pass

    @abstractmethod
    async def get_digital_twin(
        self, twin_id: UUID | None = None, patient_id: UUID | None = None
    ) -> dict[str, Any] | None:
        """
        Retrieve a Digital Twin by ID or patient ID.

        Args:
            twin_id: Optional unique identifier for the Digital Twin
            patient_id: Optional unique identifier for the patient

        Returns:
            The Digital Twin record if found, None otherwise

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the retrieval fails
        """
        pass

    @abstractmethod
    async def simulate_intervention(
        self,
        twin_id: UUID,
        intervention: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Simulate the effect of an intervention on a digital twin.

        Args:
            twin_id: Digital twin identifier
            intervention: Intervention details

        Returns:
            Dictionary containing simulation results

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the simulation fails
        """
        pass

    @abstractmethod
    async def generate_comprehensive_insights(
        self, patient_id: UUID, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Generate comprehensive patient insights by integrating multiple ML services.
        
        Args:
            patient_id: The ID of the patient
            options: Options for controlling which insights to generate
                include_symptom_forecast: Whether to include symptom forecasting
                include_biometric_correlations: Whether to include biometric correlations
                include_medication_predictions: Whether to include medication predictions
                forecast_days: Number of days to forecast symptoms
                biometric_lookback_days: Number of days to look back for biometric data
        
        Returns:
            A dictionary containing comprehensive patient insights

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the generation fails
        """
        pass
