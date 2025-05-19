"""
Mock MentaLLaMA Service - Infrastructure Implementation

This module implements a mock service for the MentaLLaMA API in the infrastructure
layer, maintaining clean architecture principles.
"""

from typing import Any, Dict, List, Optional

# Import the actual implementation from the canonical location
from app.infrastructure.ml.mentallama.mocks.mock_mentalllama_service import (
    MockMentalLLaMAService,
)

# Re-export the service class
__all__ = ["MockMentalLLaMAService"]
