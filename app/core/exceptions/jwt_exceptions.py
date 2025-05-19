# backend/app/core/exceptions/jwt_exceptions.py


class JWTError(Exception):
    """Base exception for JWT related errors."""

    def __init__(self, message: str = "JWT processing error"):
        self.message = message
        super().__init__(self.message)


class TokenExpiredError(JWTError):
    """Raised when a JWT token has expired."""

    def __init__(self, message: str = "Token has expired"):
        super().__init__(message)


class InvalidTokenError(JWTError):
    """Raised when a JWT token is invalid (e.g., signature mismatch, bad format)."""

    def __init__(self, message: str = "Invalid token"):
        super().__init__(message)


class MissingTokenError(JWTError):
    """Raised when a JWT token is expected but not found."""

    def __init__(self, message: str = "Missing token"):
        super().__init__(message)
