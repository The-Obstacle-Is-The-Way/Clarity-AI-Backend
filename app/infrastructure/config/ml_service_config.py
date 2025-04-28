# -*- coding: utf-8 -*-
"""
ML Service Configuration for NOVAMIND.

This module configures the ML services and adapters for dependency injection,
following Clean Architecture principles and ensuring proper separation of concerns.
"""

import os
from typing import Any, Dict

from app.domain.interfaces.ml_service_interface import (
    BiometricCorrelationInterface,
    DigitalTwinServiceInterface,
    PharmacogenomicsInterface,
    SymptomForecastingInterface,
)
from app.infrastructure.ml.adapters import (
    BiometricCorrelationAdapter,
    DigitalTwinServiceAdapter,
    PharmacogenomicsAdapter,
    SymptomForecastingAdapter,
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


class MLServiceConfig:
    """
    Configuration for ML services and adapters.

    This class provides factory methods for creating ML services and adapters,
    following the dependency injection pattern to ensure proper separation of
    concerns and testability.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the ML service configuration.

        Args:
            config: Configuration dictionary
        """
        self.config = config

        # Set up model directories
        self.model_base_dir = config.get("model_base_dir", "models")
        os.makedirs(self.model_base_dir, exist_ok=True)

        self.symptom_dir = os.path.join(self.model_base_dir, "symptom_forecasting")
        self.biometric_dir = os.path.join(self.model_base_dir, "biometric_correlation")
        self.pharma_dir = os.path.join(self.model_base_dir, "pharmacogenomics")

        os.makedirs(self.symptom_dir, exist_ok=True)
        os.makedirs(self.biometric_dir, exist_ok=True)
        os.makedirs(self.pharma_dir, exist_ok=True)

    def create_symptom_forecasting_service(self) -> SymptomForecastingService:
        """
        Create a symptom forecasting service.

        Returns:
            Symptom forecasting service
        """
        return SymptomForecastingService(model_dir=self.symptom_dir)

    def create_biometric_correlation_service(self) -> BiometricCorrelationService:
        """
        Create a biometric correlation service.

        Returns:
            Biometric correlation service
        """
        return BiometricCorrelationService(model_dir=self.biometric_dir)

    def create_pharmacogenomics_service(self) -> PharmacogenomicsService:
        """
        Create a pharmacogenomics service.

        Returns:
            Pharmacogenomics service
        """
        return PharmacogenomicsService(model_dir=self.pharma_dir)

    def create_digital_twin_integration_service(self) -> DigitalTwinIntegrationService:
        """
        Create a digital twin integration service.

        Returns:
            Digital twin integration service
        """
        # Create individual services
        symptom_service = self.create_symptom_forecasting_service()
        biometric_service = self.create_biometric_correlation_service()
        pharma_service = self.create_pharmacogenomics_service()

        # Create integration service
        return DigitalTwinIntegrationService(
            model_base_dir=self.model_base_dir,
            symptom_forecasting_service=symptom_service,
            biometric_correlation_service=biometric_service,
            pharmacogenomics_service=pharma_service,
        )

    def create_symptom_forecasting_adapter(self) -> SymptomForecastingInterface:
        """
        Create a symptom forecasting adapter.

        Returns:
            Symptom forecasting adapter
        """
        service = self.create_symptom_forecasting_service()
        return SymptomForecastingAdapter(service)

    def create_biometric_correlation_adapter(self) -> BiometricCorrelationInterface:
        """
        Create a biometric correlation adapter.

        Returns:
            Biometric correlation adapter
        """
        service = self.create_biometric_correlation_service()
        return BiometricCorrelationAdapter(service)

    def create_pharmacogenomics_adapter(self) -> PharmacogenomicsInterface:
        """
        Create a pharmacogenomics adapter.

        Returns:
            Pharmacogenomics adapter
        """
        service = self.create_pharmacogenomics_service()
        return PharmacogenomicsAdapter(service)

    def create_digital_twin_service_adapter(self) -> DigitalTwinServiceInterface:
        """
        Create a digital twin service adapter.

        Returns:
            Digital twin service adapter
        """
        service = self.create_digital_twin_integration_service()
        return DigitalTwinServiceAdapter(service)

    def create_all_adapters(self) -> Dict[str, Any]:
        """
        Create all adapters.

        Returns:
            Dictionary containing all adapters
        """
        return {
            "symptom_forecasting": self.create_symptom_forecasting_adapter(),
            "biometric_correlation": self.create_biometric_correlation_adapter(),
            "pharmacogenomics": self.create_pharmacogenomics_adapter(),
            "digital_twin": self.create_digital_twin_service_adapter(),
        }
