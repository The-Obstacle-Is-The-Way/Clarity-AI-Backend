"""
Exception classes for token-related errors.

This module defines exceptions that can be raised by token operations,
such as JWT token validation, generation, and verification.
"""

from app.domain.exceptions.base_exceptions import AuthenticationError

class TokenException(AuthenticationError):
    """Base class for token-related exceptions."""
    def __init__(self, message: str = "Token error"):
        super().__init__(message)

class InvalidTokenException(TokenException):
    """Exception raised when a token is invalid."""
    def __init__(self, message: str = "Invalid token"):
        super().__init__(message)

class TokenExpiredException(TokenException):
    """Exception raised when a token has expired."""
    def __init__(self, message: str = "Token has expired"):
        super().__init__(message)

class TokenBlacklistedException(TokenException):
    """Exception raised when a token has been blacklisted."""
    def __init__(self, message: str = "Token has been blacklisted"):
        super().__init__(message)

class TokenGenerationException(TokenException):
    """Exception raised when token generation fails."""
    def __init__(self, message: str = "Failed to generate token"):
        super().__init__(message)

class MissingTokenException(TokenException):
    """Exception raised when a required token is missing."""
    def __init__(self, message: str = "Token is missing"):
        super().__init__(message)

# Aliases for backward compatibility
InvalidTokenError = InvalidTokenException
TokenExpiredError = TokenExpiredException
MissingTokenError = MissingTokenException 