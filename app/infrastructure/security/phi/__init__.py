"""
HIPAA-compliant PHI (Protected Health Information) protection.

This package provides a comprehensive and consolidated implementation for detecting,
sanitizing, and protecting PHI in accordance with HIPAA regulations, following
clean architecture principles.
"""

from enum import Enum

# Core PHI protection components
from .sanitizer import (
    PHISanitizer,
    SanitizedLogger,
    get_sanitized_logger,
    RedactionStrategy,
    PatternRepository,
    redact_ssn,
    redact_phone,
    redact_email,
    redact_name,
    redact_address
)

# Middleware for API protection
from .middleware import (
    PHIMiddleware,
    add_phi_middleware,
    get_phi_middleware
)

# PHI detection patterns
from .patterns import PHI_PATTERNS

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

__all__ = [
    # Core components
    'PHISanitizer',
    'SanitizedLogger',
    'get_sanitized_logger',
    'RedactionStrategy',
    'PatternRepository',
    
    # Middleware components
    'PHIMiddleware',
    'add_phi_middleware',
    'get_phi_middleware',
    
    # Utilities and types
    'PHIType',
    'PHI_PATTERNS',
    'redact_ssn',
    'redact_phone',
    'redact_email',
    'redact_name',
    'redact_address'
]