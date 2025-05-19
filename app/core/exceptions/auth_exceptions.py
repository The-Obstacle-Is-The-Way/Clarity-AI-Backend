"""
Authentication and Authorization Exception Classes.

This module defines exceptions related to authentication and authorization.
"""

from app.core.exceptions.base_exceptions import ApplicationError


class AuthenticationError(ApplicationError):
    """Base exception for authentication errors."""

    def __init__(self, message: str = "Authentication failed", *args, **kwargs):
        """
        Initialize authentication error.

        Args:
            message: Error message
            args: Additional positional arguments
            kwargs: Additional keyword arguments
        """
        super().__init__(message, *args, **kwargs)


class AuthorizationError(ApplicationError):
    """Exception raised when a user is not authorized to perform an action."""

    def __init__(
        self, message: str = "Not authorized to perform this action", *args, **kwargs
    ):
        """
        Initialize authorization error.

        Args:
            message: Error message
            args: Additional positional arguments
            kwargs: Additional keyword arguments
        """
        super().__init__(message, *args, **kwargs)


class TokenExpiredError(AuthenticationError):
    """Exception raised when an authentication token has expired."""

    def __init__(
        self, message: str = "Authentication token has expired", *args, **kwargs
    ):
        """
        Initialize token expired error.

        Args:
            message: Error message
            args: Additional positional arguments
            kwargs: Additional keyword arguments
        """
        super().__init__(message, *args, **kwargs)


class InvalidTokenError(AuthenticationError):
    """Exception raised when an authentication token is invalid."""

    def __init__(self, message: str = "Invalid authentication token", *args, **kwargs):
        """
        Initialize invalid token error.

        Args:
            message: Error message
            args: Additional positional arguments
            kwargs: Additional keyword arguments
        """
        super().__init__(message, *args, **kwargs)
