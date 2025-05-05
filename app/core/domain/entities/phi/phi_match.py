"""
Defines the PHIMatch entity representing a detected piece of PHI.
"""

from dataclasses import dataclass


@dataclass
class PHIMatch:
    """Represents a single instance of detected PHI."""
    text: str
    pattern_name: str  # The name/category of the pattern that matched
    start: int         # Start index in the original text
    end: int           # End index in the original text
