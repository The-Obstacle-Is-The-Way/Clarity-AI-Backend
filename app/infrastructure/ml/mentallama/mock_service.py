"""
MentaLLaMA Mock Service.

This module provides a mock implementation of the MentaLLaMA service,
used for testing without requiring the actual OpenAI API dependency.
"""

from typing import Any

# Import exceptions used in interface methods if needed
from app.core.exceptions import InvalidRequestError, ServiceUnavailableError

# Import the interface
from app.core.services.ml.interface import MentaLLaMAInterface
from app.core.utils.logging import get_logger
from app.infrastructure.ml.mentallama.models import MentaLLaMAResult
from app.infrastructure.ml.phi_detection.service import PHIDetectionService


# Rename class and inherit from interface
class MockMentaLLaMA(MentaLLaMAInterface):
    """
    Mock implementation of the MentaLLaMAInterface for testing.
    
    This mock service simulates interactions with the MentaLLaMA API
    for clinical text analysis in a test environment.
    """
    
    def __init__(
        self,
        phi_detection_service: PHIDetectionService,
        api_key: str | None = None,
        api_endpoint: str = "https://api.mentallama.com/v1",
        model_name: str = "mentallama-7b",
        temperature: float = 0.7
    ):
        """
        Initialize MentaLLaMA service.
        
        Args:
            phi_detection_service: Service for detecting and redacting PHI
            api_key: MentaLLaMA API key
            api_endpoint: MentaLLaMA API endpoint
            model_name: Model to use for analysis
            temperature: Temperature parameter for model
        """
        self.logger = get_logger(__name__)
        self._phi_detection_service = phi_detection_service # Use private attribute convention
        self._api_key = api_key
        self._api_endpoint = api_endpoint
        self._model_name = model_name
        self._temperature = temperature
        self._initialized = False # Add initialized flag

    # --- Implement MentaLLaMAInterface Methods ---

    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the mock service."""
        # Optionally use config to update parameters
        self._api_key = config.get("api_key", self._api_key)
        self._api_endpoint = config.get("api_endpoint", self._api_endpoint)
        self._model_name = config.get("model_name", self._model_name)
        self._temperature = config.get("temperature", self._temperature)
        # Assume phi_detection_service is passed during __init__ or via config
        phi_service = config.get("phi_detection_service")
        if phi_service:
             self._phi_detection_service = phi_service
        
        if not hasattr(self, '_phi_detection_service') or self._phi_detection_service is None:
             # If still no PHI service, maybe raise or use a default mock?
             # For now, let's assume it was provided or is not strictly needed for all mock ops
             self.logger.warning("MockMentaLLaMA initialized without a PHI detection service.")
             # self._phi_detection_service = MagicMock(spec=PHIDetectionService) # Example: Use MagicMock if needed

        self._initialized = True
        self.logger.info(f"MockMentaLLaMA initialized with model: {self._model_name}")

    def is_healthy(self) -> bool:
        """Check if the mock service is healthy (initialized)."""
        return self._initialized

    def shutdown(self) -> None:
        """Shutdown the mock service."""
        self._initialized = False
        self.logger.info("MockMentaLLaMA shutdown.")

    def _ensure_initialized(self):
        """Raise error if not initialized."""
        if not self._initialized:
            raise ServiceUnavailableError("MockMentaLLaMA service not initialized.")

    def process( # Removed async
        self,
        text: str,
        model_type: str | None = None, # model_type might map to analysis_type
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Mock processing text - delegates to analyze_text."""
        self._ensure_initialized()
        if not text:
            raise InvalidRequestError("Input text cannot be empty.")

        # Map model_type to analysis_type if provided, otherwise use 'general'
        analysis_type = model_type if model_type else "general"

        # Use existing analyze_text logic (now synchronous)
        result_obj = self.analyze_text( # Removed await
            text=text,
            analysis_type=analysis_type,
            anonymize_phi=options.get("anonymize_phi", True) if options else True
        )
        # Return a dictionary representation as per interface
        return result_obj.dict() # Assuming MentaLLaMAResult has a dict() method

    def detect_depression( # Removed async
        self,
        text: str,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Mock depression detection."""
        self._ensure_initialized()
        if not text:
             raise InvalidRequestError("Input text cannot be empty.")

        self.logger.info(f"Mock detecting depression for text snippet: '{text[:50]}...'")
        # Simulate based on keywords
        has_depression_keywords = any(word in text.lower() for word in ["sad", "hopeless", "down", "depressed"])

        return {
            "detected": has_depression_keywords,
            "confidence": 0.75 if has_depression_keywords else 0.25,
            "indicators": ["low_mood", "anhedonia"] if has_depression_keywords else [],
            "model": self._model_name,
            "mock": True
        }

    # --- Keep existing analyze_text and helpers, make them sync ---
    def analyze_text( # Removed async
        self,
        text: str,
        analysis_type: str = "general",
        anonymize_phi: bool = True
    ) -> MentaLLaMAResult:
        """
        Analyze text using MentaLLaMA.

        This method simulates sending text to MentaLLaMA for analysis,
        with optional PHI anonymization for HIPAA compliance.

        Args:
            text: Text to analyze
            analysis_type: Type of analysis to perform
            anonymize_phi: Whether to anonymize PHI before analysis

        Returns:
            Analysis result

        Raises:
            MentaLLaMAError: If analysis fails
        """
        # Anonymize PHI if requested
        processed_text = text
        if anonymize_phi:
            # Use the potentially updated private attribute
            if hasattr(self, '_phi_detection_service') and self._phi_detection_service:
                 # Treat PHI service calls as synchronous within the mock
                 contains = self._phi_detection_service.contains_phi(text) if hasattr(self._phi_detection_service, 'contains_phi') else False # Removed await
                 if contains:
                     processed_text = self._phi_detection_service.redact_phi(text) if hasattr(self._phi_detection_service, 'redact_phi') else "[REDACTED]" # Removed await
                     self.logger.info("PHI detected and redacted before MentaLLaMA analysis")
            else:
                 self.logger.warning("PHI detection skipped: No PHI service available in MockMentaLLaMA.")

        # Generate mock analysis results based on analysis type
        if analysis_type == "general":
            analysis_result = self._generate_general_analysis(processed_text)
        elif analysis_type == "risk_assessment":
            analysis_result = self._generate_risk_assessment(processed_text)
        elif analysis_type == "treatment_recommendation":
            analysis_result = self._generate_treatment_recommendation(processed_text)
        else:
            analysis_result = {"note": f"Mock analysis for type: {analysis_type}"}
            
        # Create and return result
        return MentaLLaMAResult(
            text=processed_text, # Use the potentially processed text
            analysis=analysis_result,
            confidence=0.85, # Mock confidence
            metadata={
                "model": self._model_name, # Use private attribute
                "analysis_type": analysis_type,
                "mock": True
            }
        )
        
    def _generate_general_analysis(self, text: str) -> dict[str, Any]:
        """
        Generate mock general analysis.
        
        Args:
            text: Processed text to analyze
            
        Returns:
            Mock analysis results
        """
        return {
            "insights": [
                "Patient shows signs of moderate anxiety",
                "Sleep disturbance noted in patient history"
            ],
            "suggested_actions": [
                "Consider anxiety screening using GAD-7",
                "Evaluate sleep patterns with sleep diary"
            ],
            "risk_factors": {
                "anxiety": 0.8,
                "depression": 0.4,
                "substance_use": 0.1
            }
        }
        
    def _generate_risk_assessment(self, text: str) -> dict[str, Any]:
        """
        Generate mock risk assessment.
        
        Args:
            text: Processed text to analyze
            
        Returns:
            Mock risk assessment results
        """
        return {
            "risk_level": "moderate",
            "primary_concerns": [
                "Anxiety symptoms",
                "Difficulty sleeping"
            ],
            "risk_factors": {
                "anxiety": 0.8,
                "depression": 0.4,
                "substance_use": 0.1,
                "suicidal_ideation": 0.0
            },
            "suggested_actions": [
                "Regular check-ins",
                "Sleep hygiene education"
            ]
        }
        
    def _generate_treatment_recommendation(self, text: str) -> dict[str, Any]:
        """
        Generate mock treatment recommendation.
        
        Args:
            text: Processed text to analyze
            
        Returns:
            Mock treatment recommendation results
        """
        return {
            "treatment_options": [
                "Cognitive Behavioral Therapy (CBT)",
                "Mindfulness-based stress reduction"
            ],
            "medication_considerations": [
                "Consider SSRI if symptoms persist",
                "Start with low dose"
            ],
            "lifestyle_recommendations": [
                "Sleep hygiene improvements",
                "Regular exercise",
                "Stress management techniques"
            ]
        }
    
    # Keep close method for potential backward compatibility if tests use it,
    # but shutdown is the interface method.
    def close(self) -> None: # Removed async
        """Alias for shutdown for potential compatibility."""
        self.shutdown()
