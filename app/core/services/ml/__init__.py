"""
ML Services Package.

This package provides mental health machine learning services including:
- MentaLLaMA: Mental health language model analysis service
- PHI Detection: Protected Health Information detection service
- Digital Twin: Patient digital twin simulation service
- PAT: Patient Assessment Tool for clinical evaluation
"""

from app.core.services.ml.factory import MLServiceCache, MLServiceFactory
from app.core.services.ml.interface import (
    BaseMLInterface as MLService,  # Keep alias if needed elsewhere for now
)
from app.core.services.ml.interface import PHIDetectionInterface  # Corrected: Remove alias
from app.core.services.ml.interface import (
    DigitalTwinInterface,
    MentaLLaMAInterface,
)

# from app.core.services.ml.mentalllama import MentaLLaMA # REMOVE: No such module in core.services.ml
# from app.core.services.ml.mock import MockMentaLLaMA # REMOVE: Use infrastructure layer for real/mock services
from app.core.services.ml.pat import BedrockPAT  # Added
from app.core.services.ml.pat import (  # PATService, # Removed
    MockPATService,
    PATInterface,
)

__all__ = [
    # Base implementations
    # "MentaLLaMA", # REMOVE: Not in this layer
    # "PATService", # Removed
    "BedrockPAT",  # Added
    "DigitalTwinInterface",
    # Interfaces
    "MLService",
    "MLServiceCache",
    # Factory and cache
    "MLServiceFactory",
    "MentaLLaMAInterface",
    # Mock implementations
    # "MockMentaLLaMA", # REMOVE: Not in this layer
    "MockPATService",
    "PATInterface",
    "PHIDetectionInterface",  # Corrected: Use actual interface name
]
