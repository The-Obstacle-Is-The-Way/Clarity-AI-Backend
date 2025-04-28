# -*- coding: utf-8 -*-
"""
ML Service Providers Package.

This module serves as the package initialization for ML service providers.
"""

# Corrected import: AWSBedrockMentaLLaMA is the actual class name
# Removed BedrockDigitalTwin and BedrockPHIDetection as they don't exist in aws_bedrock.py
from app.core.services.ml.providers.aws_bedrock import (
    AWSBedrockMentaLLaMA,
)


# Updated __all__ to reflect the available class
__all__ = [
    "AWSBedrockMentaLLaMA",
]