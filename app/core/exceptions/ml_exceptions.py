"""
Machine Learning Service Exceptions.

This module defines exceptions raised by machine learning services.
"""

from typing import Any

from app.core.exceptions.base_exceptions import ApplicationError


class MLServiceError(ApplicationError):
    """Base exception for ML service errors."""

    def __init__(self, message: str = "ML service error", *args, **kwargs):
        """
        Initialize ML service error.

        Args:
            message: Error message
        """
        super().__init__(message, *args, **kwargs)


class PHIDetectionError(MLServiceError):
    """Exception raised for errors in PHI detection."""

    def __init__(self, message: str = "Error in PHI detection", *args, **kwargs):
        """
        Initialize PHI detection error.

        Args:
            message: Error message
        """
        super().__init__(message, *args, **kwargs)


class PHISecurityError(MLServiceError):
    """
    Exception raised for PHI-related security issues.

    This exception is used specifically for security-related errors in PHI processing,
    such as detection failures that could lead to PHI leakage.
    """

    def __init__(self, message: str = "PHI security error detected", *args, **kwargs):
        """
        Initialize PHI security error.

        Args:
            message: Error message
        """
        super().__init__(message, *args, **kwargs)


class MentalLLaMAServiceError(MLServiceError):
    """
    Exception raised for errors in MentalLLaMA service operations.

    This exception is typically raised for service-level issues like
    configuration problems, service unavailability, or unexpected responses.
    """

    def __init__(
        self,
        message: str = "Error in MentalLLaMA service",
        service_name: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
        *args,
        **kwargs,
    ):
        """
        Initialize MentalLLaMA service error.

        Args:
            message: Error message
            service_name: Name of the specific service component that failed
            status_code: HTTP status code or other error code if applicable
            details: Additional error details
        """
        self.service_name = service_name
        self.status_code = status_code
        self.details = details or {}

        if service_name:
            message = f"{message} in {service_name}"
        if status_code:
            message = f"{message} (Status Code: {status_code})"

        super().__init__(message, *args, **kwargs)


class MentalLLaMAInferenceError(MLServiceError):
    """
    Exception raised when the MentalLLaMA model fails during inference.

    This exception is specifically for errors in the inference process,
    such as invalid inputs, model execution failures, or unexpected outputs.
    """

    def __init__(
        self,
        message: str = "MentalLLaMA inference error",
        model_id: str | None = None,
        input_data: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
        *args,
        **kwargs,
    ):
        """
        Initialize MentalLLaMA inference error.

        Args:
            message: Error message
            model_id: Identifier of the specific model that failed
            input_data: Input data that caused the failure (sanitized of any PHI)
            details: Additional error details
        """
        self.model_id = model_id
        self.input_data = input_data
        self.details = details or {}

        if model_id:
            message = f"{message} in model {model_id}"

        super().__init__(message, *args, **kwargs)


class XGBoostServiceError(MLServiceError):
    """Exception raised for errors in XGBoost service."""

    def __init__(self, message: str = "Error in XGBoost service", *args, **kwargs):
        """
        Initialize XGBoost service error.

        Args:
            message: Error message
        """
        super().__init__(message, *args, **kwargs)


class InvalidRequestError(MLServiceError):
    """Exception raised for invalid request parameters or inputs."""

    def __init__(
        self,
        message: str = "Invalid request parameters",
        parameter: str = None,
        *args,
        **kwargs,
    ):
        """
        Initialize invalid request error.

        Args:
            message: Error message
            parameter: The specific parameter that is invalid
            args: Additional positional arguments
            kwargs: Additional keyword arguments
        """
        self.parameter = parameter
        if parameter:
            message = f"{message}: {parameter}"
        super().__init__(message, *args, **kwargs)


class ModelNotFoundError(MLServiceError):
    """Exception raised when a requested ML model cannot be found."""

    def __init__(self, model_id: str = None, *args, **kwargs):
        """
        Initialize model not found error.

        Args:
            model_id: ID of the model that was not found
            args: Additional positional arguments
            kwargs: Additional keyword arguments
        """
        message = "ML model not found"
        if model_id:
            message = f"{message}: {model_id}"
        self.model_id = model_id
        super().__init__(message, *args, **kwargs)


class ServiceUnavailableError(MLServiceError):
    """Exception raised when an ML service is unavailable or uninitialized."""

    def __init__(self, service_name: str = None, reason: str = None, *args, **kwargs):
        """
        Initialize service unavailable error.

        Args:
            service_name: Name of the service that is unavailable
            reason: Reason for service unavailability
            args: Additional positional arguments
            kwargs: Additional keyword arguments
        """
        message = "ML service unavailable"
        if service_name:
            message = f"{service_name} service unavailable"
        if reason:
            message = f"{message}: {reason}"
        self.service_name = service_name
        self.reason = reason
        super().__init__(message, *args, **kwargs)


class DigitalTwinError(MLServiceError):
    """Exception raised for errors specific to Digital Twin operations."""

    def __init__(
        self, message: str = "Error in Digital Twin operation", *args, **kwargs
    ):
        """
        Initialize Digital Twin error.

        Args:
            message: Error message
        """
        super().__init__(message, *args, **kwargs)
