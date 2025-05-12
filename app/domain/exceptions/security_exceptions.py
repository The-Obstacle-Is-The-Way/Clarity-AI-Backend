"""
Exception classes for security-related errors.

This module defines exceptions that can be raised by security-related operations,
such as authentication, authorization, and access control.
"""

from app.domain.exceptions.base_exceptions import AuthorizationError, BaseApplicationError

class SecurityError(BaseApplicationError):
    """General exception for security-related errors."""
    def __init__(self, message: str = "A security error occurred"):
        super().__init__(message)

class PHIAccessError(AuthorizationError):
    """Exception raised specifically for unauthorized attempts to access PHI."""
    def __init__(self, message: str = "Unauthorized access to Protected Health Information (PHI)"):
        super().__init__(message)

class PermissionDeniedError(AuthorizationError):
    """Exception raised when a user lacks required permissions."""
    def __init__(self, message: str = "Permission denied"):
        super().__init__(message)

class InvalidCredentialsError(SecurityError):
    """Exception raised when credentials are invalid."""
    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(message)

class AccountLockedError(SecurityError):
    """Exception raised when a user account is locked."""
    def __init__(self, message: str = "Account is locked"):
        super().__init__(message)

class AccountDisabledError(SecurityError):
    """Exception raised when a user account is disabled."""
    def __init__(self, message: str = "Account is disabled"):
        super().__init__(message)

class TooManyAttemptsError(SecurityError):
    """Exception raised when too many authentication attempts are made."""
    def __init__(self, message: str = "Too many authentication attempts"):
        super().__init__(message)

class InvalidSessionError(SecurityError):
    """Exception raised when a session is invalid."""
    def __init__(self, message: str = "Invalid session"):
        super().__init__(message)

class SessionExpiredError(SecurityError):
    """Exception raised when a session has expired."""
    def __init__(self, message: str = "Session has expired"):
        super().__init__(message) 