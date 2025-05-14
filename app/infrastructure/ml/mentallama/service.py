"""
MentaLLaMA Service Module.

This module provides the MentaLLaMA service implementation following
clean architecture principles with proper separation of concerns.
"""

# Import and re-export the actual implementation for backward compatibility
from app.infrastructure.ml.mentallama.mocks.mock_mentalllama_service import (
    MockMentalLLaMAService,
)

# Import the actual implementation from within this package
from app.infrastructure.ml.mentallama.mock_service import MockMentaLLaMA

# Export all relevant service classes
__all__ = ["MockMentaLLaMA", "MockMentalLLaMAService"]
