"""
Actigraphy Service Interface

This module defines the interface for the actigraphy service, which is responsible
for processing and analyzing actigraphy data. This interface follows the Interface
Segregation Principle (ISP) from SOLID design principles.
"""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ActigraphyServiceInterface(Protocol):
    """Interface for actigraphy data processing and analysis services."""

    async def initialize(self) -> None:
        """Initialize the actigraphy service."""
        ...

    async def analyze_actigraphy(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        device_info: dict[str, Any] | None = None,
        analysis_types: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Analyze actigraphy data to extract relevant features and patterns.

        Args:
            patient_id: The ID of the patient whose data is being analyzed
            readings: List of actigraphy readings (typically from wearable device)
            device_info: Optional information about the device used
            analysis_types: Optional list of specific analysis types to perform
            **kwargs: Additional parameters for the analysis

        Returns:
            Analysis results including metrics, patterns, and summary
        """
        ...

    async def get_embeddings(
        self, patient_id: str, readings: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        """
        Generate embeddings from actigraphy data for use in machine learning models.

        Args:
            patient_id: The ID of the patient
            readings: Optional list of actigraphy readings
            **kwargs: Additional parameters

        Returns:
            Embeddings derived from the actigraphy data
        """
        ...

    async def get_analysis_by_id(
        self, analysis_id: str, patient_id: str | None = None
    ) -> dict[str, Any]:
        """
        Retrieve a previously performed analysis by its ID.

        Args:
            analysis_id: The ID of the analysis to retrieve
            patient_id: Optional patient ID for authorization verification

        Returns:
            The complete analysis results
        """
        ...

    async def get_patient_analyses(
        self, patient_id: str, limit: int = 10, offset: int = 0
    ) -> dict[str, Any]:
        """
        Retrieve all analyses performed for a specific patient.

        Args:
            patient_id: The ID of the patient
            limit: Maximum number of analyses to return
            offset: Number of analyses to skip (for pagination)

        Returns:
            List of analyses for the patient
        """
        ...

    async def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the current actigraphy analysis model.

        Returns:
            Model metadata including version, capabilities, and performance metrics
        """
        ...

    async def get_analysis_types(self) -> list[str]:
        """
        Get available analysis types supported by the service.

        Returns:
            List of supported analysis types
        """
        ...

    async def integrate_with_digital_twin(
        self,
        patient_id: str,
        analysis_id: str,
        profile_id: str | None = None,
        integration_options: dict[str, bool] | None = None,
    ) -> dict[str, Any]:
        """
        Integrate actigraphy analysis results with a patient's digital twin.

        Args:
            patient_id: The ID of the patient
            analysis_id: The ID of the analysis to integrate
            profile_id: Optional ID of the digital twin profile
            integration_options: Optional configuration for the integration

        Returns:
            Results of the integration process
        """
        ...
