"""MentaLLaMA service package for mental health text analysis."""

"""Module re-exports the canonical mock implementation from mocks package.

This follows clean architecture principles by centralizing mocks in a single location
while maintaining a logical import structure for consumers of this module.
"""

# Import the canonical implementation from the mocks package
from app.infrastructure.services.mocks.mock_mentalllama_service import MockMentalLLaMAService

__all__ = ["MockMentalLLaMAService"]
