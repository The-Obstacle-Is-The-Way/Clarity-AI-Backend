"""
ClinicalSignificance entity for Digital Twin domain.
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class ClinicalSignificance:
    """Minimal stub for ClinicalSignificance domain entity."""
    significance_type: str
    description: Optional[str] = None
    level: Optional[float] = None
