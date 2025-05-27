# backend/app/core/exceptions/jwt_exceptions.py

from typing import Any


class JWTError(Exception):
    """Base exception for JWT related errors."""

    def __init__(
        self,
        message: str = "JWT processing error",
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize a JWTError exception.

        Args:
            message: Human-readable error message describing the JWT processing error
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        self.message = message
        super().__init__(message, *args, **kwargs)


class TokenExpiredError(JWTError):
    """Raised when a JWT token has expired."""

    def __init__(
        self,
        message: str = "Token has expired",
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize a TokenExpiredError exception.

        Args:
            message: Human-readable error message describing the token expiry
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        super().__init__(message, *args, **kwargs)


class InvalidTokenError(JWTError):
    """Raised when a JWT token is invalid (e.g., signature mismatch, bad format)."""

    def __init__(
        self,
        message: str = "Invalid token",
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize an InvalidTokenError exception.

        Args:
            message: Human-readable error message describing the token invalidity
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        super().__init__(message, *args, **kwargs)


class MissingTokenError(JWTError):
    """Raised when a JWT token is expected but not found."""

    def __init__(
        self,
        message: str = "Missing token",
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize a MissingTokenError exception.

        Args:
            message: Human-readable error message describing the missing token
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        super().__init__(message, *args, **kwargs)
