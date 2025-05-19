"""
ML Service Interfaces.

This module defines the interfaces for ML services used in the application.
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseMLInterface(ABC):
    """Base interface for all ML services."""

    @abstractmethod
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.

        Args:
            config: Configuration dictionary

        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.

        Returns:
            True if healthy, False otherwise
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        pass


class MentaLLaMAInterface(BaseMLInterface):
    """Interface for MentaLLaMA ML services."""

    @abstractmethod
    def process(
        self,
        text: str,
        model_type: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Process text using the MentaLLaMA model.

        Args:
            text: Text to process
            model_type: Type of model to use
            options: Additional processing options

        Returns:
            Processing results

        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
            ModelNotFoundError: If model type is not found
        """
        pass

    @abstractmethod
    def detect_depression(
        self, text: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Detect depression signals in text.

        Args:
            text: Text to analyze
        """
        pass


class PHIDetectionInterface(BaseMLInterface):
    """Interface for PHI detection services."""

    @abstractmethod
    def detect_phi(self, text: str) -> list[dict[str, Any]]:
        """
        Detect potential PHI entities in the given text.

        Args:
            text: The input text to analyze.

        Returns:
            A list of detected PHI entities, each represented as a dictionary
            containing details like 'text', 'type', 'score', 'begin_offset', 'end_offset'.
            Returns an empty list if no PHI is detected.

        Raises:
            ServiceUnavailableError: If the detection service is unavailable.
            InvalidRequestError: If the input text is invalid.
        """
        pass

    @abstractmethod
    def redact_phi(self, text: str, replacement: str = "[PHI]") -> str:
        """
        Redact detected PHI entities in the text.

        Args:
            text: The input text containing potential PHI.
            replacement: The string to replace detected PHI with. Defaults to "[PHI]".

        Returns:
            The text with detected PHI entities replaced.

        Raises:
            ServiceUnavailableError: If the detection service is unavailable.
            InvalidRequestError: If the input text is invalid.
        """
        pass


class DigitalTwinInterface(BaseMLInterface):
    """Interface for Digital Twin services."""

    @abstractmethod
    def create_digital_twin(
        self, patient_id: str, initial_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a new digital twin for a patient.

        Args:
            patient_id: The ID of the patient.
            initial_data: Initial data to populate the twin.

        Returns:
            A dictionary containing the status or details of the created twin.
        """
        pass

    @abstractmethod
    def get_twin_status(self, twin_id: str) -> dict[str, Any]:
        """
        Get the current status of a digital twin.

        Args:
            twin_id: The ID of the digital twin.

        Returns:
            A dictionary containing the status information.
        """
        pass

    @abstractmethod
    def update_twin_data(self, twin_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """
        Update the data associated with a digital twin.

        Args:
            twin_id: The ID of the digital twin.
            data: The data to update.

        Returns:
            A dictionary confirming the update status.
        """
        pass

    @abstractmethod
    def get_insights(self, twin_id: str, insight_types: list[str]) -> dict[str, Any]:
        """
        Generate insights from the digital twin's data.

        Args:
            twin_id: The ID of the digital twin.
            insight_types: A list of specific insight types to generate.

        Returns:
            A dictionary containing the requested insights.
        """
        pass

    @abstractmethod
    def interact(
        self, twin_id: str, query: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Interact with the digital twin, potentially asking questions or running simulations.

        Args:
            twin_id: The ID of the digital twin.
            query: The interaction query or command.
            context: Optional context for the interaction.

        Returns:
            A dictionary containing the result of the interaction.
        """
        pass


# ... (all other interface/class definitions remain unchanged)

# Export MLService as a canonical alias for BaseMLInterface for compatibility and clarity
MLService = BaseMLInterface  # Keep this alias for now if other parts rely on it
