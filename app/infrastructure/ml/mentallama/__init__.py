"""
MentaLLaMA Integration Module.

This package provides integration with MentaLLaMA for clinical text analysis
and decision support.
"""

from app.infrastructure.ml.mentallama.mock_service import (
    MockMentaLLaMA,  # Import correct class name
)
from app.infrastructure.ml.mentallama.models import MentaLLaMAResult

__all__ = ["MentaLLaMAResult", "MockMentaLLaMA"] # Update __all__
