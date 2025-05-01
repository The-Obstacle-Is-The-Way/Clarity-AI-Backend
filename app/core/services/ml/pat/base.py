from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class PATServiceBase(ABC):
    """Abstract Base Class for the Patient Assessment Tool (PAT) Service."""

    _config: Optional[Dict[str, Any]] = None

    def __init__(self, config: Dict[str, Any]):
        """Initialize the base service with configuration."""
        self._config = config

    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize the PAT service implementation."""
        pass

    @abstractmethod
    def analyze_actigraphy(self, data: Any, analysis_id: str) -> Dict[str, Any]:
        """Analyze actigraphy data."""
        pass

    @abstractmethod
    def get_actigraphy_embeddings(self, data: Any, analysis_id: str) -> Dict[str, Any]:
        """Generate embeddings from actigraphy data."""
        pass

    @abstractmethod
    def get_analysis_by_id(self, analysis_id: str) -> Dict[str, Any]:
        """Retrieve analysis results by ID."""
        pass

    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the underlying model."""
        pass

    @abstractmethod
    def integrate_with_digital_twin(self, analysis_id: str, twin_id: str) -> Dict[str, Any]:
        """Integrate analysis results with a digital twin."""
        pass

    # Note: _sanitize_phi is an internal helper in AWSPATService, not part of the public interface
