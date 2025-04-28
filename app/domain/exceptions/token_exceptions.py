"""
Token related exceptions.

This module defines exceptions related to token operations.
"""

from app.domain.exceptions.base import DomainException


class TokenException(DomainException):
    """Base exception for token-related errors."""
    pass


class InvalidTokenException(TokenException):
    """Exception raised when a token is invalid or malformed."""
    def __init__(self, message: str = "Invalid token"):
        super().__init__(message)


class TokenExpiredException(TokenException):
    """Exception raised when a token has expired."""
    def __init__(self, message: str = "Token has expired"):
        super().__init__(message)


class TokenBlacklistedException(TokenException):
    """Exception raised when a token has been blacklisted."""
    def __init__(self, message: str = "Token has been revoked"):
        super().__init__(message)


class TokenGenerationException(TokenException):
    """Exception raised when token generation fails."""
    def __init__(self, message: str = "Failed to generate token"):
        super().__init__(message)


class MissingTokenException(TokenException):
    """Exception raised when a token is required but missing."""
    def __init__(self, message: str = "Token is required"):
        super().__init__(message) 