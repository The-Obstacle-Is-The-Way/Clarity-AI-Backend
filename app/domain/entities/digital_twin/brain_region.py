"""
BrainRegion entity for Digital Twin domain.
"""
from dataclasses import dataclass


@dataclass
class BrainRegion:
    """Minimal stub for BrainRegion domain entity."""

    name: str
    description: str | None = None
