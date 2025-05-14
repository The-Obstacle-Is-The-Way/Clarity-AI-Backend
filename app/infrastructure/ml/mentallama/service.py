"""
MentaLLaMA Service Module

This module exports interfaces and implementations for the MentaLLaMA service.
The service analyzes clinical text to extract structured insights using
natural language processing.
"""

# Import directly for backward compatibility
from app.infrastructure.ml.mentallama.mock import MockMentaLLaMA

# Define the class alias for service compatibility
MockMentalLLaMAService = MockMentaLLaMA

# Export both names for backward compatibility
__all__ = ["MockMentaLLaMA", "MockMentalLLaMAService"]
