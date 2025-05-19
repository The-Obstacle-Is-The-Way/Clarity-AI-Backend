"""
MentaLLaMA Service Interface.

This module defines the interface for the MentalLLaMA service, which specializes in
natural language processing for mental health applications.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union


class MentaLLaMAInterface(ABC):
    """Interface for the MentaLLaMA service."""

    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the MentaLLaMA service with config parameters.

        Args:
            config: Configuration parameters
        """
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy and ready to process requests.

        Returns:
            True if healthy, False otherwise
        """
        pass

    @abstractmethod
    async def process(
        self,
        prompt: str,
        user_id: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Process a text prompt and generate a response.

        Args:
            prompt: The text prompt to process
            user_id: User ID for logging and personalization
            model: Model identifier to use
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate
            **kwargs: Additional parameters specific to the endpoint

        Returns:
            Dictionary containing the processing results
        """
        pass

    @abstractmethod
    async def detect_depression(
        self, text: str, user_id: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Detect signs of depression in text.

        Args:
            text: Text to analyze
            user_id: User ID for logging and personalization
            **kwargs: Additional parameters

        Returns:
            Dictionary with detection results and confidence scores
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Gracefully shut down the service and release resources."""
        pass
