"""
Application-specific error codes and error handling utilities.

This module defines error codes and error handling utilities for the application,
providing consistent error patterns that can be used across different layers.
"""

from enum import Enum, auto
from typing import Any, Dict, List, Optional

from app.core.exceptions.base_exceptions import ApplicationError as BaseApplicationError


class ErrorCode(str, Enum):
    """
    Error codes for the application.
    
    These codes provide a consistent way to identify different types of errors
    across the application. They can be used for logging, monitoring, and
    client-side error handling.
    """
    # General errors
    UNKNOWN = "UNKNOWN"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    
    # Validation and data errors
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    DATA_INTEGRITY_ERROR = "DATA_INTEGRITY_ERROR"
    
    # Resource errors
    NOT_FOUND = "NOT_FOUND"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    CONFLICT = "CONFLICT"
    
    # Authentication and authorization errors
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    
    # Business rule errors
    BUSINESS_RULE_VIOLATION = "BUSINESS_RULE_VIOLATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"
    
    # External service errors
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR"
    COMMUNICATION_ERROR = "COMMUNICATION_ERROR"
    
    # Infrastructure errors
    DATABASE_ERROR = "DATABASE_ERROR"
    PERSISTENCE_ERROR = "PERSISTENCE_ERROR"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    
    # HIPAA compliance errors
    HIPAA_VIOLATION = "HIPAA_VIOLATION"
    PHI_EXPOSURE = "PHI_EXPOSURE"
    SECURITY_BREACH = "SECURITY_BREACH"
    
    # Performance errors
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"


class ApplicationError(BaseApplicationError):
    """
    Application-specific error with error codes.
    
    This is a wrapper around the base ApplicationError that makes using
    the ErrorCode enum more convenient.
    
    Attributes:
        message: A human-readable error message
        detail: Additional information about the error
        code: An error code from the ErrorCode enum
    """
    
    def __init__(
        self, 
        message: str = "Application error",
        detail: Optional[str | List[str] | Dict[str, Any]] = None,
        code: ErrorCode = ErrorCode.INTERNAL_ERROR
    ):
        """
        Initialize an application error.
        
        Args:
            message: A human-readable error message
            detail: Additional information about the error
            code: An error code from the ErrorCode enum
        """
        super().__init__(message=message, detail=detail, code=code.value) 