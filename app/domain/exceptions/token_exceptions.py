"""
Exception classes related to authentication tokens.

This module defines exceptions raised during token validation, generation, and usage.
All exceptions follow HIPAA compliance for error messages.
"""

from app.domain.exceptions.base_exceptions import (
    AuthenticationError,
)


class TokenException(AuthenticationError):
    """Base class for token-related exceptions."""

    status_code = 401  # Default to 401 Unauthorized for token issues

    def __init__(self, message: str = "Authentication error", *args: object, **kwargs: object) -> None:
        # Ensure message is HIPAA compliant by avoiding sensitive details
        status_code_val = kwargs.pop("status_code", self.status_code)
        if isinstance(status_code_val, int):
            self.status_code = status_code_val
        else:
            self.status_code = self.status_code  # Keep class default
        super().__init__(message, *args, **kwargs)


class InvalidTokenException(TokenException):
    """Raised when a token is invalid."""

    def __init__(self, message: str = "Invalid authentication token", *args: object, **kwargs: object) -> None:
        super().__init__(message, status_code=401, *args, **kwargs)


class TokenExpiredException(TokenException):
    """Raised when a token has expired."""

    def __init__(self, message: str = "Authentication token has expired", *args: object, **kwargs: object) -> None:
        super().__init__(message, status_code=401, *args, **kwargs)


class TokenBlacklistedException(TokenException):
    """Raised when a token has been blacklisted."""

    def __init__(self, message: str = "Authentication token has been revoked", *args: object, **kwargs: object) -> None:
        super().__init__(message, status_code=401, *args, **kwargs)


class TokenGenerationException(TokenException):
    """Raised when a token cannot be generated."""

    status_code = 500  # Server error for generation issues

    def __init__(self, message: str = "Unable to generate authentication token", *args: object, **kwargs: object) -> None:
        super().__init__(message, status_code=500, *args, **kwargs)


class MissingTokenException(TokenException):
    """Raised when a token is required but not provided."""

    def __init__(self, message: str = "Authentication token is required", *args: object, **kwargs: object) -> None:
        super().__init__(message, status_code=401, *args, **kwargs)


# Map exception types to their status codes for easy lookup
EXCEPTION_STATUS_CODES = {
    InvalidTokenException: 401,
    TokenExpiredException: 401,
    TokenBlacklistedException: 401,
    TokenGenerationException: 500,
    MissingTokenException: 401,
}

# Aliases for backward compatibility
InvalidTokenError = InvalidTokenException
TokenExpiredError = TokenExpiredException
MissingTokenError = MissingTokenException
