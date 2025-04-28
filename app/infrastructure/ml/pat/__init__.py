"""
Pretrained Actigraphy Transformer (PAT) module.

This package provides functionality for analyzing actigraphy data from wearable devices
using transformer-based models to extract patterns related to physical activity, sleep,
and other biometric indicators relevant to mental health assessment.
"""

from app.infrastructure.ml.pat.service import PATService

__all__ = ["PATService"]