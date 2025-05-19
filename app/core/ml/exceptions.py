"""
Exceptions for ML and LLM operations in the Novamind Digital Twin Platform.

This module defines custom exception types for interacting with
machine learning and large language models, particularly MentalLLaMA.
"""
from typing import Any


class MentalLLaMABaseError(Exception):
    """Base exception for all MentalLLaMA errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        """
        Initialize the base exception.

        Args:
            message: Human-readable error message
            details: Additional error details as a dictionary
        """
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:
        """String representation of the error."""
        return self.message


class MentalLLaMAInferenceError(MentalLLaMABaseError):
    """Exception raised when inference with MentalLLaMA model fails."""

    def __init__(
        self,
        message: str,
        model_id: str | None = None,
        input_text: str | None = None,
        error_type: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        """
        Initialize inference error.

        Args:
            message: Human-readable error message
            model_id: ID or name of the model that failed
            input_text: The input text that caused the failure (should be handled carefully to avoid PHI leakage)
            error_type: Category of error (e.g., "timeout", "invalid_response")
            details: Additional error details
        """
        self.model_id = model_id
        self.input_text = (
            input_text  # Store privately but don't include in logs or string representations
        )
        self.error_type = error_type

        # Combine details, excluding input_text to prevent PHI leakage
        combined_details = {"model_id": model_id, "error_type": error_type}

        if details:
            combined_details.update(details)

        super().__init__(message, combined_details)


class MentalLLaMAValidationError(MentalLLaMABaseError):
    """Exception raised when input validation for MentalLLaMA model fails."""

    def __init__(
        self,
        message: str,
        validation_errors: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
    ):
        """
        Initialize validation error.

        Args:
            message: Human-readable error message
            validation_errors: Dictionary of validation errors
            details: Additional error details
        """
        self.validation_errors = validation_errors or {}

        # Combine validation errors with details
        combined_details = {"validation_errors": validation_errors}

        if details:
            combined_details.update(details)

        super().__init__(message, combined_details)


class MentalLLaMAServiceError(MentalLLaMABaseError):
    """Exception raised when there's an issue with the MentalLLaMA service."""

    def __init__(
        self,
        message: str,
        service_name: str | None = None,
        status_code: int | None = None,
        retry_after: int | None = None,
        details: dict[str, Any] | None = None,
    ):
        """
        Initialize service error.

        Args:
            message: Human-readable error message
            service_name: Name of the service that encountered an error
            status_code: HTTP status code (if applicable)
            retry_after: Suggested retry time in seconds (if applicable)
            details: Additional error details
        """
        self.service_name = service_name
        self.status_code = status_code
        self.retry_after = retry_after

        # Combine service details with other details
        combined_details = {
            "service_name": service_name,
            "status_code": status_code,
            "retry_after": retry_after,
        }

        if details:
            combined_details.update(details)

        super().__init__(message, combined_details)


class MentalLLaMATokenLimitError(MentalLLaMAValidationError):
    """Exception raised when input exceeds token limits."""

    def __init__(
        self,
        message: str,
        token_count: int,
        token_limit: int,
        details: dict[str, Any] | None = None,
    ):
        """
        Initialize token limit error.

        Args:
            message: Human-readable error message
            token_count: Actual token count of the input
            token_limit: Maximum allowed token count
            details: Additional error details
        """
        self.token_count = token_count
        self.token_limit = token_limit

        # Create validation errors dictionary
        validation_errors = {
            "token_count": token_count,
            "token_limit": token_limit,
            "exceeded_by": token_count - token_limit,
        }

        super().__init__(message, validation_errors, details)
