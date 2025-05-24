"""
Base exception classes for the application.

This module defines base exception classes that are extended by other
exception classes in the application.
"""


class BaseApplicationError(Exception):
    """Base class for all application exceptions."""

    def __init__(self, message: str = "An application error occurred") -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


class ValidationError(BaseApplicationError):
    """Error raised when validation fails."""

    def __init__(self, message: str = "Validation failed") -> None:
        super().__init__(message)


class AuthenticationError(BaseApplicationError):
    """Error raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message)


class AuthorizationError(BaseApplicationError):
    """Error raised when authorization fails."""

    def __init__(self, message: str = "Authorization failed") -> None:
        super().__init__(message)


class ConfigurationError(BaseApplicationError):
    """Error raised when configuration is invalid."""

    def __init__(self, message: str = "Invalid configuration") -> None:
        super().__init__(message)


class IntegrationError(BaseApplicationError):
    """Error raised when an integration with an external system fails."""

    def __init__(self, message: str = "Integration failed") -> None:
        super().__init__(message)


class BusinessRuleError(BaseApplicationError):
    """Error raised when a business rule is violated."""

    def __init__(self, message: str = "Business rule violated") -> None:
        super().__init__(message)
