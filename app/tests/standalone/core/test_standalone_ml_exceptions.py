"""
Self-contained test for Machine Learning (ML) exceptions.

This module contains both the ML exception classes and tests in a single file,
making it completely independent of the rest of the application.
"""

import pytest

import unittest
from typing import Any

# ============= ML Exception Classes =============

class MLBaseError(Exception):
    """Base class for all ML-related exceptions."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            details: Additional details for debugging and logging
        """
        self.message = message
        self.details = details or {}
        super().__init__(self.message)
        
    def add_detail(self, key: str, value: Any) -> 'MLBaseError':
        """
        Add a detail to the exception.

        Args:
            key: Detail key
            value: Detail value

        Returns:
            The exception instance (for chaining)
        """
        self.details[key] = value
        return self

    def get_detail(self, key: str, default: Any = None) -> Any:
        """
        Get a detail from the exception.

        Args:
            key: Detail key
            default: Default value if key doesn't exist

        Returns:
            The detail value or default
        """

        return self.details.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the exception to a dictionary.

        Returns:
            Dictionary representation of the exception
        """

        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details
        }


class MLInferenceError(MLBaseError):
    """Exception raised during ML model inference."""

    def __init__(
            self,
            message: str,
            model_name: str,
            input_data: Any | None = None,
            details: dict[str, Any] | None = None
    ):
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            model_name: Name of the model that caused the error
            input_data: Input data that caused the error (if available)
            details: Additional details for debugging and logging
        """
        super().__init__(message, details)
        self.model_name = model_name
        self.input_data = input_data

        # Add model-specific details
        self.add_detail("model_name", model_name)
        if input_data is not None:
            # Store only basic info about the input to avoid excessive logging
            input_type = type(input_data).__name__
            input_shape = getattr(input_data, "shape", None)
            if input_shape is not None:
                self.add_detail("input_shape", str(input_shape))
            elif isinstance(input_data, (list, tuple)):
                self.add_detail("input_length", len(input_data))
            elif isinstance(input_data, dict):
                self.add_detail("input_keys", list(input_data.keys()))
            else:
                self.add_detail("input_type", input_type)
class MLValidationError(MLBaseError):
    """Exception raised during validation of ML inputs or parameters."""

    def __init__(
        self,
        message: str,
        validation_errors: list[dict[str, Any]] | None = None,
        details: dict[str, Any] | None = None
    ):
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            validation_errors: List of specific validation errors
            details: Additional details for debugging and logging
        """
        super().__init__(message, details)
        self.validation_errors = validation_errors or []

        # Add validation errors to details
        self.add_detail("validation_errors", self.validation_errors)
        
    def add_validation_error(
        self,
        field: str,
        error: str,
        expected: Any | None = None,
        actual: Any | None = None
    ) -> 'MLValidationError':
        """
        Add a validation error.

        Args:
            field: Field that failed validation
            error: Error message
            expected: Expected value or type
            actual: Actual value or type

        Returns:
            The exception instance (for chaining)
        """
        validation_error = {
            "field": field,
            "error": error
        }

        if expected is not None:
            validation_error["expected"] = str(expected)
        if actual is not None:
            validation_error["actual"] = str(actual)
            
        self.validation_errors.append(validation_error)
        self.add_detail("validation_errors", self.validation_errors)
        return self


class MLModelNotFoundError(MLBaseError):
    """Exception raised when a requested ML model is not found."""

    def __init__(
        self,
        model_name: str,
        available_models: list[str] | None = None,
        details: dict[str, Any] | None = None
    ):
        """
        Initialize the exception.

        Args:
            model_name: Name of the model that wasn't found
            available_models: List of available models (if known)
            details: Additional details for debugging and logging
        """
        message = f"Model '{model_name}' not found"
        super().__init__(message, details)
        self.model_name = model_name
        self.available_models = available_models or []

        # Add model info to details
        self.add_detail("model_name", model_name)
        if available_models:
            self.add_detail("available_models", available_models)
class MLServiceUnavailableError(MLBaseError):
    """Exception raised when an ML service is unavailable."""

    def __init__(
        self,
        service_name: str,
        reason: str | None = None,
        retry_after: int | None = None,
        details: dict[str, Any] | None = None
    ):
        """
        Initialize the exception.

        Args:
            service_name: Name of the unavailable service
            reason: Reason for the service being unavailable
            retry_after: Suggested retry time in seconds
            details: Additional details for debugging and logging
        """
        message = f"ML service '{service_name}' is unavailable"
        if reason:
            message += f": {reason}"

        super().__init__(message, details)
        self.service_name = service_name
        self.reason = reason
        self.retry_after = retry_after

        # Add service info to details
        self.add_detail("service_name", service_name)
        if reason:
            self.add_detail("reason", reason)
        if retry_after is not None:
            self.add_detail("retry_after", retry_after)
class MLServiceRateLimitError(MLServiceUnavailableError):
    """Exception raised when an ML service rate limit is exceeded."""

    def __init__(
        self,
        service_name: str,
        limit: int,
        retry_after: int | None = None,
        details: dict[str, Any] | None = None
    ):
        """
        Initialize the exception.

        Args:
            service_name: Name of the rate-limited service
            limit: Rate limit that was exceeded
            retry_after: Suggested retry time in seconds
            details: Additional details for debugging and logging
        """
        reason = f"Rate limit of {limit} requests exceeded"
        super().__init__(service_name, reason, retry_after, details)
        self.limit = limit

        # Add rate limit info to details
        self.add_detail("limit", limit)


# ============= ML Exception Tests =============


class TestMLExceptions(unittest.TestCase):
    """Test the ML exception classes."""

    @pytest.mark.standalone()
    def test_base_error(self):
        """Test the base error class."""
        # Create a base error
        error = MLBaseError("Test error message")

        # Check message
        self.assertEqual(str(error), "Test error message")
        self.assertEqual(error.message, "Test error message")

        # Check details
        self.assertEqual(error.details, {})

        # Add a detail
        error.add_detail("test_key", "test_value")

        # Check the detail was added
        self.assertEqual(error.get_detail("test_key"), "test_value")

        # Check default value for (non-existent detail)
        self.assertIsNone(error.get_detail("non_existent"))
        self.assertEqual(error.get_detail("non_existent", "default"), "default")

        # Check to_dict
        error_dict = error.to_dict()
        self.assertEqual(error_dict["error_type"], "MLBaseError")
        self.assertEqual(error_dict["message"], "Test error message")
        self.assertEqual(error_dict["details"], {"test_key": "test_value"})

    @pytest.mark.standalone()
    def test_inference_error(self):
        """Test the inference error class."""
        # Create an inference error
        error = MLInferenceError(
            message="Failed to run inference",
            model_name="test_model",
            input_data=[1, 2, 3, 4, 5]
        )

        # Check message
        self.assertEqual(error.message, "Failed to run inference")

        # Check model name
        self.assertEqual(error.model_name, "test_model")

        # Check input data
        self.assertEqual(error.input_data, [1, 2, 3, 4, 5])

        # Check details contain model name and input info
        self.assertEqual(error.get_detail("model_name"), "test_model")
        self.assertEqual(error.get_detail("input_length"), 5)

        # Test with dictionary input
        error = MLInferenceError(
            message="Failed to run inference",
            model_name="test_model",
            input_data={"x": [1, 2, 3], "y": [4, 5, 6]}
        )

        # Check details contain keys info
        self.assertEqual(error.get_detail("input_keys"), ["x", "y"])

    @pytest.mark.standalone()
    def test_validation_error(self):
        """Test the validation error class."""
        # Create a validation error
        error = MLValidationError(
            message="Input validation failed"
        )

        # Check message
        self.assertEqual(error.message, "Input validation failed")

        # Add validation errors
        error.add_validation_error(
            field="input_shape",
            error="Invalid shape",
            expected="(batch_size, 10)",
            actual="(batch_size, 5)"
        )
        error.add_validation_error(
            field="batch_size",
            error="Value too large",
            expected="<= 32",
            actual="64"
        )

        # Check validation errors
        self.assertEqual(len(error.validation_errors), 2)
        self.assertEqual(error.validation_errors[0]["field"], "input_shape")
        self.assertEqual(error.validation_errors[0]["error"], "Invalid shape")
        self.assertEqual(error.validation_errors[0]["expected"], "(batch_size, 10)")
        self.assertEqual(error.validation_errors[0]["actual"], "(batch_size, 5)")

        # Check details
        self.assertEqual(len(error.get_detail("validation_errors")), 2)

    @pytest.mark.standalone()
    def test_model_not_found_error(self):
        """Test the model not found error class."""
        # Create a model not found error
        error = MLModelNotFoundError(
            model_name="non_existent_model",
            available_models=["model1", "model2", "model3"]
        )

        # Check message
        self.assertEqual(error.message, "Model 'non_existent_model' not found")

        # Check model name
        self.assertEqual(error.model_name, "non_existent_model")

        # Check available models
        self.assertEqual(error.available_models, ["model1", "model2", "model3"])

        # Check details
        self.assertEqual(error.get_detail("model_name"), "non_existent_model")
        self.assertEqual(error.get_detail("available_models"), ["model1", "model2", "model3"])

    @pytest.mark.standalone()
    def test_service_unavailable_error(self):
        """Test the service unavailable error class."""
        # Create a service unavailable error
        error = MLServiceUnavailableError(
            service_name="test_service",
            reason="Maintenance in progress",
            retry_after=3600
        )

        # Check message
        self.assertEqual(error.message, "ML service 'test_service' is unavailable: Maintenance in progress")

        # Check service info
        self.assertEqual(error.service_name, "test_service")
        self.assertEqual(error.reason, "Maintenance in progress")
        self.assertEqual(error.retry_after, 3600)

        # Check details
        self.assertEqual(error.get_detail("service_name"), "test_service")
        self.assertEqual(error.get_detail("reason"), "Maintenance in progress")
        self.assertEqual(error.get_detail("retry_after"), 3600)

    @pytest.mark.standalone()
    def test_rate_limit_error(self):
        """Test the rate limit error class."""
        # Create a rate limit error
        error = MLServiceRateLimitError(
            service_name="test_service",
            limit=100,
            retry_after=60
        )

        # Check message (inherited from MLServiceUnavailableError)
        self.assertEqual(error.message, "ML service 'test_service' is unavailable: Rate limit of 100 requests exceeded")

        # Check rate limit info
        self.assertEqual(error.service_name, "test_service")
        self.assertEqual(error.reason, "Rate limit of 100 requests exceeded")
        self.assertEqual(error.limit, 100)
        self.assertEqual(error.retry_after, 60)

        # Check details
        self.assertEqual(error.get_detail("service_name"), "test_service")
        self.assertEqual(error.get_detail("reason"), "Rate limit of 100 requests exceeded")
        self.assertEqual(error.get_detail("limit"), 100)
        self.assertEqual(error.get_detail("retry_after"), 60)

    @pytest.mark.standalone()
    def test_error_hierarchy(self):
        """Test the exception class hierarchy."""
        # Create instances of each exception type
        base_error = MLBaseError("Base error")
        inference_error = MLInferenceError("Inference error", "test_model")
        validation_error = MLValidationError("Validation error")
        model_not_found_error = MLModelNotFoundError("test_model")
        service_unavailable_error = MLServiceUnavailableError("test_service")
        rate_limit_error = MLServiceRateLimitError("test_service", 100)

        # Check inheritance
        self.assertIsInstance(base_error, MLBaseError)
        self.assertIsInstance(inference_error, MLBaseError)
        self.assertIsInstance(validation_error, MLBaseError)
        self.assertIsInstance(model_not_found_error, MLBaseError)
        self.assertIsInstance(service_unavailable_error, MLBaseError)
        self.assertIsInstance(rate_limit_error, MLBaseError)
        self.assertIsInstance(rate_limit_error, MLServiceUnavailableError)

        # Check specific types
        self.assertIsInstance(inference_error, MLInferenceError)
        self.assertIsInstance(validation_error, MLValidationError)
        self.assertIsInstance(model_not_found_error, MLModelNotFoundError)
        self.assertIsInstance(service_unavailable_error, MLServiceUnavailableError)
        self.assertIsInstance(rate_limit_error, MLServiceRateLimitError)
