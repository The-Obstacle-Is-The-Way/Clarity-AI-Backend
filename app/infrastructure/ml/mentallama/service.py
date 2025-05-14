"""
MentaLLaMA Service Module

This module exports interfaces and implementations for the MentaLLaMA service.
The service analyzes clinical text to extract structured insights using
natural language processing.
"""

# Import the canonical implementation from the mocks package
from app.infrastructure.ml.mentallama.mocks.mock_mentalllama_service import MockMentalLLaMAService

# Define MockMentaLLaMA as an alias for backward compatibility
MockMentaLLaMA = MockMentalLLaMAService

# Export the service for backward compatibility
__all__ = ["MockMentalLLaMAService"]
