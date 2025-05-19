"""
HIPAA-compliant PHI (Protected Health Information) protection.

This package provides a comprehensive implementation for detecting,
sanitizing, and protecting PHI in accordance with HIPAA regulations,
following clean architecture principles.
"""

from enum import Enum

# Middleware for API protection
from .middleware import PHIMiddleware, add_phi_middleware, get_phi_middleware

# Core PHI protection components
from .sanitizer import (
    PHISafeLogger,
    PHISanitizer,
    RedactionStrategy,
    get_sanitized_logger,
    get_sanitizer,
)


# PHI types for categorization
class PHIType(str, Enum):
    """Standard PHI types for categorization."""

    SSN = "SSN"
    NAME = "NAME"
    DOB = "DOB"
    ADDRESS = "ADDRESS"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    IP_ADDRESS = "IP_ADDRESS"
    MEDICAL_RECORD_NUMBER = "MRN"
    HEALTH_PLAN_NUMBER = "HEALTH_PLAN_NUMBER"
    DATE = "DATE"
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"


# Create global sanitizer instance for convenience functions
_sanitizer = get_sanitizer()


# Re-export commonly used functions for convenience
def contains_phi(text: str) -> bool:
    """Check if text contains PHI."""
    if not text or not isinstance(text, str):
        return False
    sanitized = _sanitizer.sanitize_string(text)
    return sanitized != text


def sanitize_phi(data: any) -> any:
    """Sanitize PHI in various data formats."""
    if isinstance(data, str):
        return _sanitizer.sanitize_string(data)
    elif isinstance(data, dict):
        return _sanitizer.sanitize_json(data)
    elif isinstance(data, list):
        result = []
        for item in data:
            if isinstance(item, str):
                result.append(_sanitizer.sanitize_string(item))
            elif isinstance(item, (dict, list)):
                result.append(sanitize_phi(item))
            else:
                result.append(item)
        return result
    return data


__all__ = [
    # Core components
    "PHISanitizer",
    "PHISafeLogger",
    "RedactionStrategy",
    # Convenience functions
    "contains_phi",
    "sanitize_phi",
    "get_sanitizer",
    "get_sanitized_logger",
    # Middleware components
    "PHIMiddleware",
    "add_phi_middleware",
    "get_phi_middleware",
    # Types
    "PHIType",
]
