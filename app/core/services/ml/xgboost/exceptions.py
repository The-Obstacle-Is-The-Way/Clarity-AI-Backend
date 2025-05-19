"""
Exception classes for the XGBoost service module.

This module defines custom exceptions that are raised by the XGBoost service
to provide clean error handling and meaningful error messages.
"""

from typing import Any


class XGBoostServiceError(Exception):
    """Base class for all XGBoost service exceptions."""

    def __init__(self, message: str, **kwargs):
        """
        Initialize a new XGBoost exception.

        Args:
            message: Error message
            **kwargs: Additional error context
        """
        self.message = message
        self.details = kwargs
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert exception to a dictionary for serialization.

        Returns:
            Dictionary representation of the exception
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            **self.details,
        }


class ValidationError(XGBoostServiceError):
    """Exception raised when request validation fails."""

    def __init__(
        self, message: str, field: str | None = None, value: Any = None, **kwargs
    ):
        """
        Initialize a validation error.

        Args:
            message: Error message
            field: Name of the field that failed validation
            value: Value that failed validation
            **kwargs: Additional error context
        """
        super().__init__(message, field=field, value=value, **kwargs)


class InvalidInputError(XGBoostServiceError):
    """Exception raised when the input data is invalid for processing."""

    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: Any = None,
        reason: str | None = None,
        **kwargs,
    ):
        """
        Initialize an invalid input error.

        Args:
            message: Error message
            field: Name of the field with invalid input
            value: The invalid value
            reason: Reason why the input is invalid
            **kwargs: Additional error context
        """
        super().__init__(message, field=field, value=value, reason=reason, **kwargs)


class DataPrivacyError(XGBoostServiceError):
    """Exception raised when PHI is detected in data."""

    def __init__(
        self,
        message: str,
        field: str | None = None,
        phi_type: str | None = None,
        **kwargs,
    ):
        """
        Initialize a data privacy error.

        Args:
            message: Error message
            field: Name of the field containing PHI
            phi_type: Type of PHI detected
            **kwargs: Additional error context
        """
        super().__init__(message, field=field, phi_type=phi_type, **kwargs)


class ResourceNotFoundError(XGBoostServiceError):
    """Exception raised when a requested resource is not found."""

    def __init__(
        self,
        message: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        **kwargs,
    ):
        """
        Initialize a resource not found error.

        Args:
            message: Error message
            resource_type: Type of resource that was not found
            resource_id: ID of the resource that was not found
            **kwargs: Additional error context
        """
        super().__init__(
            message, resource_type=resource_type, resource_id=resource_id, **kwargs
        )


class ModelNotFoundError(ResourceNotFoundError):
    """Exception raised when a requested ML model is not found."""

    def __init__(
        self,
        message: str,
        model_type: str | None = None,
        model_version: str | None = None,
        **kwargs,
    ):
        """
        Initialize a model not found error.

        Args:
            message: Error message
            model_type: Type of model that was not found
            model_version: Version of the model that was not found
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            resource_type="model",
            resource_id=f"{model_type}:{model_version}"
            if model_type and model_version
            else model_type,
            model_type=model_type,
            model_version=model_version,
            **kwargs,
        )


class PredictionError(XGBoostServiceError):
    """Exception raised when a prediction fails."""

    def __init__(
        self,
        message: str,
        model_type: str | None = None,
        cause: str | None = None,
        **kwargs,
    ):
        """
        Initialize a prediction error.

        Args:
            message: Error message
            model_type: Type of model that failed
            cause: Cause of the failure
            **kwargs: Additional error context
        """
        super().__init__(message, model_type=model_type, cause=cause, **kwargs)


class ServiceConnectionError(XGBoostServiceError):
    """Exception raised when a connection to an external service fails."""

    def __init__(
        self,
        message: str,
        service_name: str | None = None,
        cause: str | None = None,
        **kwargs,
    ):
        """
        Initialize a service connection error.

        Args:
            message: Error message
            service_name: Name of the service that failed
            cause: Cause of the failure
            **kwargs: Additional error context
        """
        super().__init__(message, service_name=service_name, cause=cause, **kwargs)


class ConfigurationError(XGBoostServiceError):
    """Exception raised when there is a configuration error."""

    def __init__(
        self, message: str, field: str | None = None, value: Any = None, **kwargs
    ):
        """
        Initialize a configuration error.

        Args:
            message: Error message
            field: Name of the field with an error
            value: Value that caused the error
            **kwargs: Additional error context
        """
        super().__init__(message, field=field, value=value, **kwargs)


class ServiceConfigurationError(XGBoostServiceError):
    """Exception raised when there is a configuration error with an external service."""

    def __init__(
        self,
        message: str,
        service_name: str | None = None,
        config_key: str | None = None,
        **kwargs,
    ):
        """
        Initialize a service configuration error.

        Args:
            message: Error message
            service_name: Name of the service with configuration issues
            config_key: The configuration key that has issues
            **kwargs: Additional error context
        """
        super().__init__(
            message, service_name=service_name, config_key=config_key, **kwargs
        )


class ServiceUnavailableError(XGBoostServiceError):
    """Exception raised when an external service is unavailable."""

    def __init__(
        self,
        message: str,
        service_name: str | None = None,
        retry_after: int | None = None,
        **kwargs,
    ):
        """
        Initialize a service unavailable error.

        Args:
            message: Error message
            service_name: Name of the unavailable service
            retry_after: Suggested time (in seconds) to wait before retrying
            **kwargs: Additional error context
        """
        super().__init__(
            message, service_name=service_name, retry_after=retry_after, **kwargs
        )


class ThrottlingError(XGBoostServiceError):
    """Exception raised when requests are being throttled by an external service."""

    def __init__(
        self,
        message: str,
        service_name: str | None = None,
        retry_after: int | None = None,
        **kwargs,
    ):
        """
        Initialize a throttling error.

        Args:
            message: Error message
            service_name: Name of the service that is throttling requests
            retry_after: Suggested time (in seconds) to wait before retrying
            **kwargs: Additional error context
        """
        super().__init__(
            message, service_name=service_name, retry_after=retry_after, **kwargs
        )


class FeatureValidationError(ValidationError):
    """Exception raised when feature validation fails for ML prediction."""

    def __init__(
        self,
        message: str,
        feature_name: str | None = None,
        expected_type: str | None = None,
        actual_value: Any = None,
        **kwargs,
    ):
        """
        Initialize a feature validation error.

        Args:
            message: Error message
            feature_name: Name of the feature that failed validation
            expected_type: Expected type for the feature
            actual_value: Actual value provided
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            field=feature_name,
            value=actual_value,
            expected_type=expected_type,
            **kwargs,
        )


class ModelInvocationError(XGBoostServiceError):
    """Exception raised when model invocation fails but the service itself is working."""

    def __init__(
        self,
        message: str,
        model_type: str | None = None,
        endpoint_name: str | None = None,
        status_code: int | None = None,
        **kwargs,
    ):
        """
        Initialize a model invocation error.

        Args:
            message: Error message
            model_type: Type of model that failed to invoke
            endpoint_name: Name of the endpoint that failed
            status_code: HTTP/API status code if applicable
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            model_type=model_type,
            endpoint_name=endpoint_name,
            status_code=status_code,
            **kwargs,
        )


class ModelTimeoutError(XGBoostServiceError):
    """Exception raised when a model invocation times out."""

    def __init__(
        self,
        message: str,
        model_type: str | None = None,
        endpoint_name: str | None = None,
        timeout_seconds: int | None = None,
        **kwargs,
    ):
        """
        Initialize a model timeout error.

        Args:
            message: Error message
            model_type: Type of model that timed out
            endpoint_name: Name of the endpoint that timed out
            timeout_seconds: Timeout threshold in seconds
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            model_type=model_type,
            endpoint_name=endpoint_name,
            timeout_seconds=timeout_seconds,
            **kwargs,
        )


class SerializationError(XGBoostServiceError):
    """Exception raised when serialization or deserialization fails."""

    def __init__(
        self,
        message: str,
        data_type: str | None = None,
        format_type: str | None = None,
        cause: str | None = None,
        **kwargs,
    ):
        """
        Initialize a serialization error.

        Args:
            message: Error message
            data_type: Type of data that failed to serialize/deserialize
            format_type: Format type that was attempted
            cause: Cause of the failure
            **kwargs: Additional error context
        """
        super().__init__(
            message, data_type=data_type, format_type=format_type, cause=cause, **kwargs
        )


class UnauthorizedError(XGBoostServiceError):
    """Exception raised when a user does not have authorization to access a resource."""

    def __init__(
        self,
        message: str,
        user_id: str | None = None,
        resource_id: str | None = None,
        resource_type: str | None = None,
        **kwargs,
    ):
        """
        Initialize an unauthorized error.

        Args:
            message: Error message
            user_id: ID of the user who was denied access
            resource_id: ID of the resource that was being accessed
            resource_type: Type of resource that was being accessed
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            user_id=user_id,
            resource_id=resource_id,
            resource_type=resource_type,
            **kwargs,
        )
