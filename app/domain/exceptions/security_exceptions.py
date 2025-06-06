"""
Exception classes related to security operations.

This module defines exceptions raised during authentication, authorization,
and other security-related operations.
"""

from typing import Any

from app.domain.exceptions.base_exceptions import (
    AuthenticationError,
    AuthorizationError,
    BaseApplicationError,
)


class SecurityError(BaseApplicationError):
    """Base class for security-related exceptions."""

    def __init__(self, message: str = "Security violation", *args: Any, **kwargs: Any) -> None:
        super().__init__(message, *args, **kwargs)


class PHIAccessError(SecurityError, AuthorizationError):
    """Raised when unauthorized access to PHI is attempted."""

    def __init__(
        self,
        message: str = "Unauthorized PHI access attempt",
        user_id: str | None = None,
        resource_type: str | None = None,
        action: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if user_id and resource_type and action:
            message = f"User {user_id} attempted unauthorized {action} on {resource_type} PHI"
        super().__init__(message, *args, **kwargs)
        self.user_id = user_id
        self.resource_type = resource_type
        self.action = action


class PermissionDeniedError(SecurityError, AuthorizationError):
    """Raised when a user does not have permission for an operation."""

    def __init__(
        self,
        message: str = "Permission denied",
        user_id: str | None = None,
        permission: str | None = None,
        resource: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if user_id and permission and resource:
            message = f"User {user_id} lacks permission '{permission}' for resource '{resource}'"
        elif user_id and permission:
            message = f"User {user_id} lacks permission '{permission}'"
        super().__init__(message, *args, **kwargs)
        self.user_id = user_id
        self.permission = permission
        self.resource = resource


class InvalidCredentialsError(SecurityError, AuthenticationError):
    """Raised when invalid credentials are provided."""

    def __init__(self, message: str = "Invalid credentials", *args: Any, **kwargs: Any) -> None:
        super().__init__(message, *args, **kwargs)


class AccountLockedError(SecurityError, AuthenticationError):
    """Raised when a user account is locked."""

    def __init__(
        self,
        message: str = "Account is locked",
        user_id: str | None = None,
        until: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if user_id and until:
            message = f"Account for user {user_id} is locked until {until}"
        elif user_id:
            message = f"Account for user {user_id} is locked"
        super().__init__(message, *args, **kwargs)
        self.user_id = user_id
        self.until = until


class AccountDisabledError(SecurityError, AuthenticationError):
    """Raised when a user account is disabled."""

    def __init__(
        self,
        message: str = "Account is disabled",
        user_id: str | None = None,
        reason: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if user_id and reason:
            message = f"Account for user {user_id} is disabled: {reason}"
        elif user_id:
            message = f"Account for user {user_id} is disabled"
        super().__init__(message, *args, **kwargs)
        self.user_id = user_id
        self.reason = reason


class TooManyAttemptsError(SecurityError, AuthenticationError):
    """Raised when too many failed authentication attempts occur."""

    def __init__(
        self,
        message: str = "Too many failed attempts",
        user_id: str | None = None,
        attempts: int | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if user_id and attempts:
            message = f"Too many failed attempts ({attempts}) for user {user_id}"
        super().__init__(message, *args, **kwargs)
        self.user_id = user_id
        self.attempts = attempts


class InvalidSessionError(SecurityError, AuthenticationError):
    """Raised when a session is invalid."""

    def __init__(self, message: str = "Invalid session", *args: Any, **kwargs: Any) -> None:
        super().__init__(message, *args, **kwargs)


class SessionExpiredError(SecurityError, AuthenticationError):
    """Raised when a session has expired."""

    def __init__(self, message: str = "Session has expired", *args: Any, **kwargs: Any) -> None:
        super().__init__(message, *args, **kwargs)
