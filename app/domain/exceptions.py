"""
Domain-level exceptions for the NOVAMIND application.

This module defines the exceptions that can be raised at the domain level,
providing a clear separation between domain errors and infrastructure errors.
"""

from typing import Any


class DomainException(Exception):
    """Base exception for all domain-level exceptions."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


class ValidationException(DomainException):
    """Exception raised when domain validation fails."""

    pass


class ResourceNotFoundException(DomainException):
    """Exception raised when a requested resource is not found."""

    pass


class AuthenticationError(DomainException):
    """Exception raised when authentication fails."""

    pass


class AuthorizationError(DomainException):
    """Exception raised when a user is not authorized to access a resource."""

    pass


class TokenExpiredError(AuthenticationError):
    """Exception raised when an authentication token has expired."""

    def __init__(
        self, message: str = "Token has expired", details: dict[str, Any] | None = None
    ):
        super().__init__(message, details)


class InvalidTokenError(AuthenticationError):
    """Exception raised when an authentication token is invalid."""

    def __init__(
        self, message: str = "Invalid token", details: dict[str, Any] | None = None
    ):
        super().__init__(message, details)


class MissingTokenError(AuthenticationError):
    """Exception raised when no authentication token is provided."""

    def __init__(
        self,
        message: str = "Authentication token is missing",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, details)


class BusinessRuleViolationException(DomainException):
    """Exception raised when a business rule is violated."""

    pass


class ConcurrencyException(DomainException):
    """Exception raised when concurrent modification creates a conflict."""

    pass


class IntegrationException(DomainException):
    """Exception raised when integration with external systems fails."""

    pass
