"""
MentaLLaMA Service Module.

This module provides the MentaLLaMA service implementation following
clean architecture principles with proper separation of concerns.
"""

# Import the actual implementation from within this package
from app.infrastructure.services.mocks.mock_mentalllama_service import MockMentalLLaMAService
from app.infrastructure.ml.mentallama.mock_service import MockMentaLLaMA

# Export both implementations for maximum compatibility
__all__ = ["MockMentaLLaMA", "MockMentalLLaMAService"]
