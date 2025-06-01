"""
Validation exceptions for the application.

This module defines exceptions related to validation errors,
ensuring HIPAA-compliant error handling and proper error codes.
"""

from typing import Any, Optional

from app.core.exceptions.application_error import ErrorCode
from app.core.exceptions.base_exceptions import BaseException


class ValidationError(BaseException):
    """
    Exception raised when input validation fails.
    
    This exception is used for custom validation errors that go beyond
    basic schema validation, particularly for business rule validation.
    """
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.VALIDATION_ERROR,
        errors: Optional[list[dict[str, Any]]] = None,
        status_code: int = 422,
    ):
        """
        Initialize the validation error.
        
        Args:
            message: Human-readable error message
            error_code: Specific error code
            errors: List of validation errors with details
            status_code: HTTP status code to return
        """
        super().__init__(message=message, error_code=error_code)
        self.errors = errors or []
        self.status_code = status_code
        
    def __str__(self) -> str:
        """String representation of the error."""
        if self.errors:
            return f"{self.message} - {self.errors}"
        return self.message


class DataValidationError(ValidationError):
    """Exception raised when data validation fails."""
    
    def __init__(
        self,
        message: str = "Data validation failed",
        errors: Optional[list[dict[str, Any]]] = None,
    ):
        """Initialize with default validation error code."""
        super().__init__(
            message=message,
            error_code=ErrorCode.VALIDATION_ERROR,
            errors=errors,
        )


class SchemaValidationError(ValidationError):
    """Exception raised when schema validation fails."""
    
    def __init__(
        self,
        message: str = "Schema validation failed",
        errors: Optional[list[dict[str, Any]]] = None,
    ):
        """Initialize with default schema validation error code."""
        super().__init__(
            message=message,
            error_code=ErrorCode.VALIDATION_ERROR,
            errors=errors,
        )


class BusinessRuleValidationError(ValidationError):
    """Exception raised when business rule validation fails."""
    
    def __init__(
        self,
        message: str = "Business rule validation failed",
        errors: Optional[list[dict[str, Any]]] = None,
    ):
        """Initialize with default business rule validation error code."""
        super().__init__(
            message=message,
            error_code=ErrorCode.VALIDATION_ERROR,
            errors=errors,
        )
