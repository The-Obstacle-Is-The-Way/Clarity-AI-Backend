"""MentaLLaMA service package for mental health text analysis.

This module provides advanced NLP capabilities for psychiatric note analysis,
insight extraction, and digital twin modeling. It follows clean architecture principles
with clear separation between interfaces and implementations.
"""

# Export the primary service interfaces
from app.infrastructure.ml.mentallama.service import (
    MockMentaLLaMA,
    MockMentalLLaMAService
)

__all__ = ["MockMentaLLaMA", "MockMentalLLaMAService"]
