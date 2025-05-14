"""
MentaLLaMA Service Module

This module exports interfaces and implementations for the MentaLLaMA service.
The service analyzes clinical text to extract structured insights using
natural language processing.
"""

# Import directly to provide backward compatibility
from app.infrastructure.ml.mentallama.mocks.mock_mentalllama_service import MockMentalLLaMAService

# Export the service class explicitly
__all__ = ["MockMentalLLaMAService"]

# Make the service directly available in this module for imports
MockMentalLLaMAService = MockMentalLLaMAService
