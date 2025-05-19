"""
ClinicalInsight entity for Digital Twin domain.
"""
from dataclasses import dataclass


@dataclass
class ClinicalInsight:
    """Minimal stub for ClinicalInsight domain entity."""

    insight_type: str
    description: str | None = None
    confidence: float | None = None
