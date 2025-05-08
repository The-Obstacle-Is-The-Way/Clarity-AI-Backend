"""
HIPAA-compliant PHI (Protected Health Information) protection.

This package provides a comprehensive and consolidated implementation for detecting,
sanitizing, and protecting PHI in accordance with HIPAA regulations, following
clean architecture principles.
"""

from enum import Enum

# Middleware for API protection
from .middleware import PHIMiddleware, add_phi_middleware, get_phi_middleware

# Core PHI protection components
from .sanitizer import (
    PHISanitizer,
    PHISafeLogger,
    get_sanitizer,
    get_sanitized_logger,
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

# PHI Service
from .phi_service import PHIService, RedactionMode, contains_phi, get_phi_service, sanitize_phi

__all__ = [
    # Core components
    'PHISanitizer',
    'PHISafeLogger',
    # Service
    'PHIService',
    'RedactionMode',
    'sanitize_phi',
    'contains_phi',
    'get_phi_service',
    # Sanitizer utilities
    'get_sanitizer',
    'get_sanitized_logger',
    
    # Middleware components
    'PHIMiddleware',
    'add_phi_middleware',
    'get_phi_middleware',
    
    # Types
    'PHIType',
]