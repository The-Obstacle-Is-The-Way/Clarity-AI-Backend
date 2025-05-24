"""
Base exceptions for the application.

This module defines the foundational exception classes that form the basis of the
application's exception hierarchy.
"""

from typing import Any


class BaseException(Exception):
    """
    Base exception for all application exceptions.

    Attributes:
        message: A human-readable error message
        detail: Additional information about the error
        code: An error code for machine processing
    """

    def __init__(
        self,
        message: str,
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str | None = None,
    ) -> None:
        self.message = message
        self.detail = detail
        self.code = code
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.detail:
            return f"{self.message} - {self.detail}"
        return self.message


class ValidationException(BaseException):
    """Exception raised for validation errors."""

    def __init__(
        self,
        message: str = "Validation error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "VALIDATION_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class ResourceNotFoundException(BaseException):
    """Exception raised when a requested resource is not found."""

    def __init__(
        self,
        message: str = "Resource not found",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "RESOURCE_NOT_FOUND",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class ResourceNotFoundError(BaseException):
    """
    Exception raised when a requested resource is not found.

    This is an alias for ResourceNotFoundException for backward compatibility.
    """

    def __init__(
        self,
        message: str = "Resource not found",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "RESOURCE_NOT_FOUND",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)

        if " not found" not in message:
            self.message = f"{message} not found"


class EntityNotFoundError(ResourceNotFoundError):
    """
    Exception raised when an entity cannot be found.

    This is a specialized form of ResourceNotFoundError for domain entities.
    """

    def __init__(
        self,
        message: str = "Entity not found",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "ENTITY_NOT_FOUND",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class AuthenticationException(BaseException):
    """Exception raised for authentication errors."""

    def __init__(
        self,
        message: str = "Authentication failed",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "AUTHENTICATION_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class AuthorizationException(BaseException):
    """Exception raised for authorization errors."""

    def __init__(
        self,
        message: str = "Not authorized",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "AUTHORIZATION_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class BusinessRuleException(BaseException):
    """Exception raised when a business rule is violated."""

    def __init__(
        self,
        message: str = "Business rule violation",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "BUSINESS_RULE_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class InitializationError(BaseException):
    """Exception raised when a service or component fails to initialize."""

    def __init__(
        self,
        message: str = "Failed to initialize",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "INITIALIZATION_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class ConfigurationError(BaseException):
    """Exception raised for configuration errors."""

    def __init__(
        self,
        message: str = "Configuration error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "CONFIGURATION_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class ExternalServiceException(BaseException):
    """Exception raised when an external service call fails."""

    def __init__(
        self,
        message: str = "External service error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "EXTERNAL_SERVICE_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class DatabaseException(BaseException):
    """Exception raised for database errors."""

    def __init__(
        self,
        message: str = "Database error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "DATABASE_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class PersistenceError(BaseException):
    """Exception raised for persistence layer errors."""

    def __init__(
        self,
        message: str = "Persistence error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "PERSISTENCE_ERROR",
        original_exception: Exception | None = None,
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)
        self.original_exception = original_exception


class SecurityException(BaseException):
    """Exception raised for security-related errors."""

    def __init__(
        self,
        message: str = "Security error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "SECURITY_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class ApplicationError(BaseException):
    """Base class for application-specific errors."""

    def __init__(
        self,
        message: str = "Application error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "APPLICATION_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class InvalidConfigurationError(BaseException):
    """Exception raised when configuration is invalid."""

    def __init__(
        self,
        message: str = "Invalid configuration",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "INVALID_CONFIGURATION",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class ModelExecutionError(BaseException):
    """Exception raised when an ML model fails during execution."""

    def __init__(
        self,
        message: str = "Model execution error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "MODEL_EXECUTION_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class IntegrationError(BaseException):
    """Exception raised for integration errors."""

    def __init__(
        self,
        message: str = "Integration error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "INTEGRATION_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class ServiceProviderError(BaseException):
    """Exception raised for service provider errors."""

    def __init__(
        self,
        message: str = "Service provider error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "SERVICE_PROVIDER_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class AnalysisError(BaseException):
    """Exception raised for analysis errors."""

    def __init__(
        self,
        message: str = "Analysis error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "ANALYSIS_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class EmbeddingError(BaseException):
    """Exception raised for embedding errors."""

    def __init__(
        self,
        message: str = "Embedding error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "EMBEDDING_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)


class HIPAAComplianceError(BusinessRuleException):
    """Exception raised for HIPAA compliance violations."""

    def __init__(
        self,
        message: str = "HIPAA compliance violation",
        detail: str | list[str] | dict[str, Any] | None = None,
        violation_type: str | None = None,
        code: str = "HIPAA_COMPLIANCE_ERROR",
    ) -> None:
        super().__init__(message=message, detail=detail, code=code)
        self.violation_type = violation_type


# Type aliases for backward compatibility
AuthorizationError = AuthorizationException
ValidationError = ValidationException
