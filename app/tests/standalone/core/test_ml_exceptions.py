"""
Self-contained test for ML exceptions to verify test infrastructure.

This test module includes both the necessary exception classes and tests in a single file
to validate that the test infrastructure is working correctly.
"""

import pytest
import unittest
from typing import Any


# Exception classes that would normally be in app/core/ml/exceptions.py
class MentalLLaMABaseError(Exception):
    """Base exception for all MentalLLaMA errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


class MentalLLaMAInferenceError(MentalLLaMABaseError):
    """Exception raised when inference with MentalLLaMA model fails."""

    def __init__(
        self,
        message: str,
        model_id: str | None = None,
        input_text: str | None = None,
        error_type: str | None = None,
        details: dict[str, Any] | None = None
    ):
        self.model_id = model_id
        self.input_text = input_text
        self.error_type = error_type

        # Merge additional details
        combined_details = {
            "model_id": model_id,
            "error_type": error_type
        }

        # Don't include input text in details to avoid PHI leakage in logs
        if details:
            combined_details.update(details)
        
        super().__init__(message, combined_details)


class MentalLLaMAValidationError(MentalLLaMABaseError):
    """Exception raised when input validation for MentalLLaMA model fails."""

    def __init__(
        self,
        message: str,
        validation_errors: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None
    ):
        self.validation_errors = validation_errors or {}
        
        # Merge additional details
        combined_details = {
            "validation_errors": self.validation_errors
        }
        
        if details:
            combined_details.update(details)
            
        super().__init__(message, combined_details)


class MentalLLaMATimeoutError(MentalLLaMAInferenceError):
    """Exception raised when MentalLLaMA inference times out."""

    def __init__(
        self,
        message: str = "MentalLLaMA inference timed out",
        model_id: str | None = None,
        input_text: str | None = None,
        timeout_ms: int | None = None,
        details: dict[str, Any] | None = None
    ):
        combined_details = {"timeout_ms": timeout_ms}
        
        if details:
            combined_details.update(details)
            
        super().__init__(
            message,
            model_id=model_id,
            input_text=input_text,
            error_type="timeout",
            details=combined_details
        )
        
        
        self.timeout_ms = timeout_ms


class MentalLLaMAQuotaExceededError(MentalLLaMAInferenceError):
    """Exception raised when MentalLLaMA API quota is exceeded."""

    def __init__(
        self,
        message: str = "MentalLLaMA API quota exceeded",
        model_id: str | None = None,
        input_text: str | None = None,
        quota_reset_time: str | None = None,
        details: dict[str, Any] | None = None
    ):
        combined_details = {"quota_reset_time": quota_reset_time}
        
        if details:
            combined_details.update(details)
            
        super().__init__(
            message,
            model_id=model_id,
            input_text=input_text,
            error_type="quota_exceeded",
            details=combined_details
        )
        
        
        self.quota_reset_time = quota_reset_time


# Test class
class TestMentalLLaMAExceptions(unittest.TestCase):
    """Test suite for MentalLLaMA exception classes."""

    @pytest.mark.standalone()
    def test_base_error(self):
        """Test the base error class."""
        # Arrange
        message = "Base error message"
        details = {"key": "value"}

        # Act
        error = MentalLLaMABaseError(message, details)

        # Assert
        self.assertEqual(error.message, message)
        self.assertEqual(error.details, details)
        self.assertEqual(str(error), message)

    @pytest.mark.standalone()
    def test_inference_error(self):
        """Test the inference error class."""
        # Arrange
        message = "Inference error message"
        model_id = "mentalllama-v1"
        input_text = "Sample input with PHI"
        error_type = "timeout"
        details = {"latency_ms": 15000}

        # Act
        error = MentalLLaMAInferenceError(
            message=message,
            model_id=model_id,
            input_text=input_text,
            error_type=error_type,
            details=details
        )
        
        # Assert
        self.assertEqual(error.message, message)
        self.assertEqual(error.model_id, model_id)
        self.assertEqual(error.input_text, input_text)
        self.assertEqual(error.error_type, error_type)
        self.assertEqual(error.details["model_id"], model_id)
        self.assertEqual(error.details["error_type"], error_type)
        self.assertEqual(error.details["latency_ms"], 15000)

        # Ensure input_text is NOT included in details to prevent PHI leakage
        self.assertNotIn("input_text", error.details)

    @pytest.mark.standalone()
    def test_validation_error(self):
        """Test the validation error class."""
        # Arrange
        message = "Validation error message"
        validation_errors = {
            "input_length": "Text too long (5000 tokens, max 4096)"
        }
        details = {"model_version": "2.0"}

        # Act
        error = MentalLLaMAValidationError(
            message=message,
            validation_errors=validation_errors,
            details=details
        )
        
        # Assert
        self.assertEqual(error.message, message)
        self.assertEqual(error.validation_errors, validation_errors)
        self.assertEqual(error.details["validation_errors"], validation_errors)
        self.assertEqual(error.details["model_version"], "2.0")

    @pytest.mark.standalone()
    def test_timeout_error(self):
        """Test the timeout error class."""
        # Arrange
        message = "Custom timeout message"
        model_id = "mentalllama-v1"
        input_text = "Sample input with PHI"
        timeout_ms = 30000
        details = {"request_id": "abc123"}

        # Act
        error = MentalLLaMATimeoutError(
            message=message,
            model_id=model_id,
            input_text=input_text,
            timeout_ms=timeout_ms,
            details=details
        )
        
        # Assert
        self.assertEqual(error.message, message)
        self.assertEqual(error.model_id, model_id)
        self.assertEqual(error.input_text, input_text)
        self.assertEqual(error.error_type, "timeout")
        self.assertEqual(error.timeout_ms, timeout_ms)
        self.assertEqual(error.details["timeout_ms"], timeout_ms)
        self.assertEqual(error.details["request_id"], "abc123")
        self.assertNotIn("input_text", error.details)

    @pytest.mark.standalone()
    def test_quota_exceeded_error(self):
        """Test the quota exceeded error class."""
        # Arrange
        model_id = "mentalllama-v1"
        input_text = "Sample input with PHI"
        quota_reset_time = "2023-06-01T00:00:00Z"
        details = {"monthly_limit": 10000}

        # Act
        error = MentalLLaMAQuotaExceededError(
            model_id=model_id,
            input_text=input_text,
            quota_reset_time=quota_reset_time,
            details=details
        )
        
        # Assert
        self.assertEqual(error.message, "MentalLLaMA API quota exceeded")
        self.assertEqual(error.model_id, model_id)
        self.assertEqual(error.input_text, input_text)
        self.assertEqual(error.error_type, "quota_exceeded")
        self.assertEqual(error.quota_reset_time, quota_reset_time)
        self.assertEqual(error.details["quota_reset_time"], quota_reset_time)
        self.assertEqual(error.details["monthly_limit"], 10000)
        self.assertNotIn("input_text", error.details)

    @pytest.mark.standalone()
    def test_default_values(self):
        """Test default values for exception classes."""
        # Base error with no details
        base_error = MentalLLaMABaseError("Base error")
        self.assertEqual(base_error.details, {})

        # Validation error with no validation_errors or details
        validation_error = MentalLLaMAValidationError("Validation error")
        self.assertEqual(validation_error.validation_errors, {})
        self.assertEqual(validation_error.details, {"validation_errors": {}})

        # Timeout error with defaults
        timeout_error = MentalLLaMATimeoutError()
        self.assertEqual(timeout_error.message, "MentalLLaMA inference timed out")
        self.assertEqual(timeout_error.error_type, "timeout")
        self.assertIsNone(timeout_error.model_id)
        self.assertIsNone(timeout_error.timeout_ms)

        # Quota exceeded error with defaults
        quota_error = MentalLLaMAQuotaExceededError()
        self.assertEqual(quota_error.message, "MentalLLaMA API quota exceeded")
        self.assertEqual(quota_error.error_type, "quota_exceeded")
        self.assertIsNone(quota_error.model_id)
        self.assertIsNone(quota_error.quota_reset_time)


if __name__ == "__main__":
    unittest.main()