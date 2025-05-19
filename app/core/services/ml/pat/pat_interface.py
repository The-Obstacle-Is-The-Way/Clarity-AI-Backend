"""
PAT (Pretrained Actigraphy Transformer) Service Interface.

This module defines the interface for the Physical Activity Tracking (PAT) service,
which provides actigraphy analysis and embedding generation capabilities.

This follows clean architecture principles with:
- Interface Segregation Principle: Properly separated methods for each responsibility
- Dependency Inversion: Clients depend on this abstract interface not implementations 
- Single Responsibility: Each method has one clear purpose
"""

import abc
from typing import Any


class PATInterface(abc.ABC):
    """Interface for the PAT service.

    This interface defines the contract that all PAT service implementations
    must follow, providing methods for analyzing actigraphy data, generating
    embeddings, and integrating with digital twin profiles.
    """

    @abc.abstractmethod
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the PAT service with configuration.

        Args:
            config: Configuration dictionary

        Raises:
            InitializationError: If initialization fails
        """
        pass

    @abc.abstractmethod
    def analyze_actigraphy(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: dict[str, Any],
        analysis_types: list[str],
        **kwargs,
    ) -> dict[str, Any]:
        """Analyze actigraphy data and return insights.

        Args:
            patient_id: Unique identifier for the patient
            readings: List of accelerometer readings
            start_time: ISO-8601 formatted start time
            end_time: ISO-8601 formatted end time
            sampling_rate_hz: Sampling rate in Hz
            device_info: Information about the device
            analysis_types: List of analysis types to perform
            **kwargs: Additional parameters for future extensibility

        Returns:
            Dictionary containing analysis results

        Raises:
            ValidationError: If input validation fails
            AnalysisError: If analysis fails
            InitializationError: If service is not initialized
        """
        pass

    @abc.abstractmethod
    def get_actigraphy_embeddings(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        **kwargs,
    ) -> dict[str, Any]:
        """Generate embeddings from actigraphy data.

        Args:
            patient_id: Unique identifier for the patient
            readings: List of accelerometer readings
            start_time: ISO-8601 formatted start time
            end_time: ISO-8601 formatted end time
            sampling_rate_hz: Sampling rate in Hz
            **kwargs: Additional parameters for future extensibility

        Returns:
            Dictionary containing embedding vector and metadata

        Raises:
            ValidationError: If input validation fails
            EmbeddingError: If embedding generation fails
            InitializationError: If service is not initialized
        """
        pass

    @abc.abstractmethod
    def get_analysis_by_id(self, analysis_id: str) -> dict[str, Any]:
        """Retrieve an analysis by its ID.

        Args:
            analysis_id: Unique identifier for the analysis

        Returns:
            Dictionary containing the analysis

        Raises:
            ResourceNotFoundError: If the analysis is not found
            InitializationError: If service is not initialized
        """
        pass

    @abc.abstractmethod
    def get_patient_analyses(
        self,
        patient_id: str,
        limit: int = 10,
        offset: int = 0,
        analysis_type: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Retrieve analyses for a patient.

        Args:
            patient_id: Unique identifier for the patient
            limit: Maximum number of analyses to return
            offset: Offset for pagination
            analysis_type: Optional filter by analysis type
            start_date: Optional filter by start date
            end_date: Optional filter by end date
            **kwargs: Additional parameters for future extensibility

        Returns:
            Dictionary containing the analyses and pagination information

        Raises:
            InitializationError: If service is not initialized
        """
        pass

    @abc.abstractmethod
    def get_model_info(self) -> dict[str, Any]:
        """Get information about the PAT model.

        Returns:
            Dictionary containing model information

        Raises:
            InitializationError: If service is not initialized
        """
        pass

    @abc.abstractmethod
    def integrate_with_digital_twin(
        self,
        patient_id: str,
        profile_id: str,
        analysis_id: str | None = None,
        actigraphy_analysis: dict[str, Any] | None = None,
        integration_types: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Integrate actigraphy analysis with a digital twin profile.
            patient_id: Patient identifier
            profile_id: Digital twin profile identifier
            actigraphy_analysis: Results from actigraphy analysis
            **kwargs: Additional parameters

        Returns:
            Dict containing integrated digital twin profile
        """
        pass

    # ---------------------------------------------------------------------------
    # Optional convenience methods
    # ---------------------------------------------------------------------------

    def get_analysis_types(self) -> list[str]:
        """Return the list of analysis types supported by the service.

        PAT service implementations may override this method when they
        support a custom or dynamic set of analyses.  A sane default is
        provided so that existing subclasses that have not yet been updated
        remain concrete and instantiable.
        """

        # Import lazily to prevent import‑cycle issues.
        try:
            from app.presentation.api.schemas.actigraphy import AnalysisType

            return [t.value for t in AnalysisType]
        except Exception:  # pragma: no cover – fallback safeguard
            # In the unlikely event that the import fails we still return the
            # canonical list hard‑coded here so that the API does not break.
            return [
                "sleep_quality",
                "activity_levels",
                "gait_analysis",
                "tremor_analysis",
            ]
