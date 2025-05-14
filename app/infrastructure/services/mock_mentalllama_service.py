"""
Mock implementation of the MentaLLaMA Service.
Provides a redirection to the canonical implementation in the mocks package,
following Clean Architecture principles with proper separation of concerns.
"""

# Re-export from the canonical implementation for backward compatibility
from app.infrastructure.ml.mentallama.mocks.mock_mentalllama_service import (
    MockMentalLLaMAService,
)

# Export all relevant service classes to maintain a clean interface
__all__ = ["MockMentalLLaMAService"]
