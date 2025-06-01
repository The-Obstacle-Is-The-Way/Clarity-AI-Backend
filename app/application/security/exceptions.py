"""
Security-related exceptions for the application layer.

This module re-exports domain exceptions and defines application-specific
security exceptions following clean architecture principles.
"""

from app.domain.exceptions import (
    AuthenticationError as DomainAuthenticationError,
    InvalidTokenError as DomainInvalidTokenError,
)
from app.domain.exceptions.security_exceptions import (
    InvalidCredentialsError as DomainCredentialsError,
)


class AuthenticationError(DomainAuthenticationError):
    """Application-level authentication error."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message)


class CredentialsException(DomainCredentialsError):
    """Application-level invalid credentials error."""

    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(message)


class InvalidTokenError(DomainInvalidTokenError):
    """Application-level invalid token error."""

    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(message)


class UserNotFoundException(AuthenticationError):
    """Raised when a user is not found during authentication."""

    def __init__(self, message: str = "User not found"):
        super().__init__(message)
