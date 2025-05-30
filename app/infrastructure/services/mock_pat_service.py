"""
Mock PAT Service - Clean Architecture Implementation

This module provides a mock implementation of the PAT service interface
for testing purposes. It follows clean architecture principles by
implementing the domain service interface.
"""

from typing import Any
from uuid import uuid4


class MockPATService:
    """
    Mock implementation of the PAT service.
    Used for testing and development without requiring external dependencies.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the mock PAT service.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self._initialized = True
        self._analysis_model_id = "mock-pat-model-1"
        self._sessions: dict[str, dict[str, Any]] = {}

    async def initialize(self) -> bool:
        """
        Initialize the service.

        Returns:
            True if initialization is successful
        """
        self._initialized = True
        return True

    async def shutdown(self) -> bool:
        """
        Shut down the service and release resources.

        Returns:
            True if shutdown is successful
        """
        self._initialized = False
        return True

    async def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the model used by this service.

        Returns:
            Dictionary containing model metadata
        """
        return {
            "model_id": self._analysis_model_id,
            "version": "1.0.0",
            "name": "Mock PAT Model",
            "description": "Mock implementation of PAT for testing",
            "capabilities": ["text_analysis", "pattern_recognition"],
            "metadata": {
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-01T00:00:00Z",
                "provider": "Clarity AI",
                "environment": "testing",
            },
        }

    async def analyze_text(
        self, text: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Analyze text using the PAT service.

        Args:
            text: The text to analyze
            options: Optional configuration options

        Returns:
            Analysis results
        """
        options = options or {}
        session_id = str(uuid4())

        # Create mock analysis result
        result = {
            "session_id": session_id,
            "model_id": self._analysis_model_id,
            "input_text": text,
            "sentiment": (
                "neutral"
                if "neutral" in text.lower()
                else "positive" if "good" in text.lower() else "negative"
            ),
            "patterns": [
                (
                    {
                        "name": "concern",
                        "confidence": 0.85,
                        "matches": ["worried", "concern", "afraid"],
                    }
                    if "worried" in text.lower()
                    else {
                        "name": "satisfaction",
                        "confidence": 0.92,
                        "matches": ["happy", "glad", "satisfied"],
                    }
                )
            ],
            "metadata": {
                "analysis_timestamp": "2025-05-14T15:00:00Z",
                "processing_time_ms": 120,
                "options_applied": list(options.keys()),
            },
        }

        # Store session for future reference
        self._sessions[session_id] = result

        return result

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Retrieve a previously created analysis session.

        Args:
            session_id: The ID of the session to retrieve

        Returns:
            Session data if found, None otherwise
        """
        return self._sessions.get(session_id)
