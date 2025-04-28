# -*- coding: utf-8 -*-
"""
PHI Detection Package.

This package provides functionality for detecting and redacting
Protected Health Information (PHI) from text content.
"""

from app.infrastructure.ml.phi_detection.service import PHIDetectionService

__all__ = ["PHIDetectionService"]