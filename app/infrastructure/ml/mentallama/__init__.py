# -*- coding: utf-8 -*-
"""
MentaLLaMA Integration Module.

This package provides integration with MentaLLaMA for clinical text analysis
and decision support.
"""

from app.infrastructure.ml.mentallama.models import MentaLLaMAResult
from app.infrastructure.ml.mentallama.mock_service import MockMentaLLaMA # Import correct class name

__all__ = ["MockMentaLLaMA", "MentaLLaMAResult"] # Update __all__
