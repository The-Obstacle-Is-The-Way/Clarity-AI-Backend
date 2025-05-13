"""
Exception classes related to authentication tokens.

This module defines exceptions raised during token validation, generation, and usage.
"""

from app.domain.exceptions.base_exceptions import BaseApplicationError, AuthenticationError


class TokenException(AuthenticationError):
    """Base class for token-related exceptions."""
    
    def __init__(self, message: str = "Token error", *args, **kwargs):
        super().__init__(message, *args, **kwargs)


class InvalidTokenException(TokenException):
    """Raised when a token is invalid."""
    
    def __init__(self, message: str = "Invalid token", *args, **kwargs):
        super().__init__(message, *args, **kwargs)


class TokenExpiredException(TokenException):
    """Raised when a token has expired."""
    
    def __init__(self, message: str = "Token has expired", *args, **kwargs):
        super().__init__(message, *args, **kwargs)


class TokenBlacklistedException(TokenException):
    """Raised when a token has been blacklisted."""
    
    def __init__(self, message: str = "Token has been blacklisted", *args, **kwargs):
        super().__init__(message, *args, **kwargs)


class TokenGenerationException(TokenException):
    """Raised when a token cannot be generated."""
    
    def __init__(self, message: str = "Failed to generate token", *args, **kwargs):
        super().__init__(message, *args, **kwargs)


class MissingTokenException(TokenException):
    """Raised when a token is required but not provided."""
    
    def __init__(self, message: str = "Token is required but not provided", *args, **kwargs):
        super().__init__(message, *args, **kwargs)


# Aliases for backward compatibility
InvalidTokenError = InvalidTokenException
TokenExpiredError = TokenExpiredException
MissingTokenError = MissingTokenException 