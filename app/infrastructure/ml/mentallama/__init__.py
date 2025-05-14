"""MentaLLaMA service package for mental health text analysis.

This module provides advanced NLP capabilities for psychiatric note analysis,
insight extraction, and digital twin modeling. It follows clean architecture principles
with clear separation between interfaces and implementations.
"""

# Export the service interfaces directly
from app.infrastructure.ml.mentallama.mock import MockMentaLLaMA

__all__ = ["MockMentaLLaMA"]
