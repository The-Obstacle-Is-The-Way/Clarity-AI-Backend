"""
Application Configuration for NOVAMIND.

This module configures the main application components and dependencies,
following Clean Architecture principles and ensuring proper separation of concerns.
"""

from typing import Any

from app.domain.repositories.patient_repository import PatientRepository
from app.domain.services.digital_twin_service import DigitalTwinService
from app.infrastructure.config.ml_service_config import MLServiceConfig
from app.infrastructure.persistence.sqlalchemy.config.database import Database
from app.infrastructure.persistence.sqlalchemy.repositories.digital_twin_repository import (
    DigitalTwinRepositoryImpl,
)
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepository,
)


class AppConfig:
    """
    Main application configuration.

    This class provides factory methods for creating application components,
    following the dependency injection pattern to ensure proper separation of
    concerns and testability.
    """

    def __init__(self, config: dict[str, Any]):
        """
        Initialize the application configuration.

        Args:
            config: Configuration dictionary
        """
        self.config = config

        # Create database configuration
        self.db_config = Database(config.get("database", {}))

        # Create ML service configuration
        self.ml_config = MLServiceConfig(config.get("ml_services", {}))

        # Create patient repository
        self.patient_repo = PatientRepository(self.db_config.session)

        # Create digital twin repository
        self.digital_twin_repo = DigitalTwinRepositoryImpl(
            db_session_factory=self.db_config.create_session_factory()
        )

    def create_digital_twin_service(self) -> DigitalTwinService:
        """
        Create a digital twin service.

        Returns:
            Digital twin service
        """
        # Create ML service adapters
        adapters = self.ml_config.create_all_adapters()

        # Create digital twin service
        self.digital_twin_service = DigitalTwinService(
            digital_twin_repository=self.digital_twin_repo,
            patient_repository=self.patient_repo,
            digital_twin_service=adapters["digital_twin"],
            symptom_forecasting_service=adapters["symptom_forecasting"],
            biometric_correlation_service=adapters["biometric_correlation"],
            pharmacogenomics_service=adapters["pharmacogenomics"],
        )
        return self.digital_twin_service

    def create_application(self) -> dict[str, Any]:
        """
        Create the main application components.

        Returns:
            Dictionary containing application components
        """
        return {
            "digital_twin_service": self.create_digital_twin_service(),
            # Add other services as needed
        }
