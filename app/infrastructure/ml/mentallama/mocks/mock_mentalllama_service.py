"""
MentaLLaMA Mock Service Module - Clean Architecture Implementation

This module provides the service implementation of MentaLLaMA that meets
the clean architecture requirements and integrates with the core domain
logic for mental health analysis.
"""

from typing import Any, ClassVar

from app.infrastructure.ml.mentallama.mock import MockMentaLLaMA


class MockMentalLLaMAService(MockMentaLLaMA):
    """
    Service implementation of the MentaLLaMA API for production-ready testing.
    This class extends the mock implementation with proper service architecture.
    """

    # Class-level shared state for stateful operations
    _sessions: ClassVar[dict[str, dict[str, Any]]] = {}
    _digital_twins: ClassVar[dict[str, dict[str, Any]]] = {}

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the MentaLLaMA service with the provided configuration.

        Args:
            config: Configuration for the service (optional)

        Raises:
            InvalidConfigurationError: If the configuration is invalid
        """
        super().__init__()
        self.config = config or {}

    # Service methods that delegate to the mock implementation
    def analyze_sentiment(self, text: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Analyze sentiment in text, returning emotions and valence."""
        return super().analyze_sentiment(text, options)

    def analyze_wellness_dimensions(
        self,
        text: str,
        dimensions: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Analyze wellness dimensions in text."""
        return super().analyze_wellness_dimensions(text, dimensions, options)

    def detect_depression(self, text: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Detect depression indicators in text."""
        return super().detect_depression(text, options)

    def assess_risk(
        self, text: str, risk_type: str | None = None, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Assess risk factors in text."""
        return super().assess_risk(text, risk_type, options)

    def generate_digital_twin(
        self,
        text_data: list[str] | None = None,
        demographic_data: dict[str, Any] | None = None,
        medical_history: dict[str, Any] | None = None,
        treatment_history: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None,
        patient_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a digital twin based on user profile and clinical data.

        This implementation adapts the service interface to match the parent class signature.
        """
        # For backward compatibility with old code that might call this with the old signature
        # We don't actually need to check the type here since we're just passing through
        return super().generate_digital_twin(
            text_data, demographic_data, medical_history, treatment_history, options, patient_id
        )

    def create_digital_twin_session(
        self, twin_id: str, session_type: str = "therapy", options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Create a new session with a digital twin."""
        return super().create_digital_twin_session(twin_id, session_type, options)

    def get_digital_twin_session(self, session_id: str) -> dict[str, Any]:
        """Get session information for a digital twin session."""
        return super().get_digital_twin_session(session_id)

    def send_message_to_session(
        self, session_id: str, message: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send a message to a digital twin session."""
        return super().send_message_to_session(session_id, message, options)

    def end_digital_twin_session(
        self, session_id: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """End a digital twin session."""
        return super().end_digital_twin_session(session_id, options)
