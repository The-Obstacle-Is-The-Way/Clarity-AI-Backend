# app/core/interfaces/ml/pat.py
import abc
from typing import Any


class PATServiceInterface(abc.ABC):
    """
    Abstract Base Class defining the interface for a PAT (PHI Anonymization and Tagging) service.
    """

    @abc.abstractmethod
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the service with necessary configuration."""
        raise NotImplementedError

    @abc.abstractmethod
    def analyze_text(self, text: str) -> dict[str, Any]:
        """Analyze the input text for PHI and other relevant information."""
        raise NotImplementedError

    @abc.abstractmethod
    def store_result(self, result_id: str, analysis_result: dict[str, Any]) -> None:
        """Store the analysis result."""
        raise NotImplementedError

    @abc.abstractmethod
    def retrieve_result(self, result_id: str) -> dict[str, Any] | None:
        """Retrieve a previously stored analysis result."""
        raise NotImplementedError

    @abc.abstractmethod
    def process_document(self, document_path: str) -> dict[str, Any]:
        """Process a document (potentially involving download, analysis, storage)."""
        raise NotImplementedError

    # Add other essential methods if needed based on AWSPATService or other implementations
