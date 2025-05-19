"""
Authentication and authorization exception classes.

This module contains custom exceptions related to authentication and authorization
that maintain HIPAA compliance by preventing leakage of sensitive information.
"""

from app.domain.exceptions.base import DomainException


class AuthenticationException(DomainException):
    """Base class for all authentication related exceptions."""

    def __init__(
        self,
        message: str = "Authentication error",
        status_code: int | None = None,
        *args,
        **kwargs,
    ):
        super().__init__(message, *args, **kwargs)
        # Set status_code if provided, otherwise subclasses might set it or it defaults
        # when handled by API layer. For generic AuthenticationException, it might be 401 or 403.
        if status_code is not None:
            self.status_code = status_code
        # else: # Don't default here, let it be None or set by subclasses / handlers
        # self.status_code = 401


class AuthorizationException(DomainException):
    """Base class for all authorization related exceptions."""

    def __init__(self, message: str = "Authorization error", *args, **kwargs):
        super().__init__(message, *args, **kwargs)


class InvalidCredentialsException(AuthenticationException):
    """Exception raised when authentication credentials are invalid."""

    def __init__(self, message: str = "Invalid credentials", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 401


class AccountLockedException(AuthenticationException):
    """Exception raised when a user account is locked due to security concerns."""

    def __init__(self, message: str = "Account locked", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 401


class AccountDisabledException(AuthenticationException):
    """Exception raised when a user account is disabled."""

    def __init__(self, message: str = "Account disabled", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 401


class TokenExpiredException(AuthenticationException):
    """Exception raised when a token has expired."""

    def __init__(self, message: str = "Token expired", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 401


class InvalidTokenException(AuthenticationException):
    """Exception raised when a token is invalid."""

    def __init__(self, message: str = "Invalid token", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 401


class TokenBlacklistedException(AuthenticationException):
    """Exception raised when a token has been blacklisted."""

    def __init__(self, message: str = "Token revoked", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 401


class SessionExpiredException(AuthenticationException):
    """Exception raised when a user session has expired."""

    def __init__(self, message: str = "Session expired", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 401


class InsufficientPermissionsException(AuthorizationException):
    """Exception raised when a user does not have sufficient permissions."""

    def __init__(self, message: str = "Insufficient permissions", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 403


class RoleRequiredException(AuthorizationException):
    """Exception raised when a specific role is required for an operation."""

    def __init__(self, message: str = "Role required", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 403


class MaxSessionsExceededException(AuthenticationException):
    """Exception raised when a user has exceeded the maximum number of active sessions."""

    def __init__(self, message: str = "Maximum sessions exceeded", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 401


class UserNotFoundException(AuthenticationException):
    """Raised when an authentication attempt refers to a non-existent user."""

    pass


class UserAlreadyExistsException(AuthenticationException):
    """Exception raised when attempting to register a user that already exists."""

    def __init__(self, message: str = "User with this email already exists", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.status_code = 409  # HTTP 409 Conflict is appropriate
