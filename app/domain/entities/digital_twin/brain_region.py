"""
BrainRegion entity for Digital Twin domain.
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class BrainRegion:
    """Minimal stub for BrainRegion domain entity."""
    name: str
    description: Optional[str] = None
