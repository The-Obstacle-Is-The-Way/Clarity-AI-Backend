"""
MentaLLaMA Mock Service Redirect Module.

This module redirects imports to the canonical implementation following
clean architecture principles with proper separation of concerns.
"""

from app.infrastructure.services.mocks.mock_mentalllama_service import MockMentalLLaMAService

# Ensure backward compatibility with any code still using the old location
__all__ = ["MockMentalLLaMAService"]
