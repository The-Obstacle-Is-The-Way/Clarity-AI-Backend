"""
ClinicalInsight entity for Digital Twin domain.
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class ClinicalInsight:
    """Minimal stub for ClinicalInsight domain entity."""
    insight_type: str
    description: Optional[str] = None
    confidence: Optional[float] = None
