"""
Domain enums related to Protected Health Information (PHI).
"""

from enum import Enum

class PHIType(str, Enum):
    """Enumeration of different types of Protected Health Information."""
    NAME = "NAME"
    SSN = "SSN"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    # Add other potential PHI types as needed (e.g., ADDRESS, DATE_OF_BIRTH)
