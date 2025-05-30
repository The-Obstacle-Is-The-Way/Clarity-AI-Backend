"""
ClinicalSignificance entity for Digital Twin domain.
"""

from dataclasses import dataclass


@dataclass
class ClinicalSignificance:
    """Minimal stub for ClinicalSignificance domain entity."""

    significance_type: str
    description: str | None = None
    level: float | None = None
