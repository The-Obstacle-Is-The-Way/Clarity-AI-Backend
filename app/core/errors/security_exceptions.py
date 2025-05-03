"""
Security-related exceptions for authentication and authorization.

This module defines security-specific exceptions following clean architecture
principles. These exceptions represent domain-specific error conditions related
to security features like authentication, authorization, and access control.
"""

from typing import Optional
from app.core.errors.base_exceptions import BaseAppException


class SecurityException(BaseAppException):
    """Base class for all security-related exceptions."""
    pass


class InvalidCredentialsError(SecurityException):
    """
    Exception raised when authentication credentials are invalid.
    
    This could be due to incorrect password, expired token, 
    or malformed authentication data.
    """
    def __init__(self, message: str = "Invalid authentication credentials provided", detail: Optional[dict] = None):
        super().__init__(message, detail=detail)


class TokenExpiredError(InvalidCredentialsError):
    """Exception raised when an authentication token has expired."""
    def __init__(self, message: str = "Authentication token has expired", detail: Optional[dict] = None):
        super().__init__(message, detail=detail)


class TokenValidationError(InvalidCredentialsError):
    """Exception raised when token validation fails for reasons other than expiration."""
    def __init__(self, message: str = "Authentication token validation failed", detail: Optional[dict] = None):
        super().__init__(message, detail=detail)


class InsufficientPermissionsError(SecurityException):
    """
    Exception raised when a user lacks the permissions required to perform an action.
    
    This represents an authorization failure rather than an authentication failure.
    """
    def __init__(self, message: str = "Insufficient permissions to perform this action", 
                 required_permissions: Optional[list] = None, 
                 detail: Optional[dict] = None):
        if required_permissions:
            if detail is None:
                detail = {}
            detail['required_permissions'] = required_permissions
        super().__init__(message, detail=detail)


class SessionExpiredError(SecurityException):
    """Exception raised when a user's session has expired (HIPAA compliance)."""
    def __init__(self, message: str = "Your session has expired, please login again", detail: Optional[dict] = None):
        super().__init__(message, detail=detail)


class RateLimitExceededError(SecurityException):
    """Exception raised when API rate limits are exceeded."""
    def __init__(self, message: str = "Rate limit exceeded", 
                 retry_after: Optional[int] = None,
                 detail: Optional[dict] = None):
        if retry_after:
            if detail is None:
                detail = {}
            detail['retry_after'] = retry_after
        super().__init__(message, detail=detail)