"""
Machine Learning exceptions for the Novamind Digital Twin Backend.

This module defines domain-level exceptions related to ML operations,
particularly for the MentalLLaMA model interactions.
"""
from typing import Any


class MentalLLaMABaseException(Exception):
    """
    Base exception for all MentalLLaMA model errors.
    
    This serves as the parent class for all MentalLLaMA-related
    exceptions, providing consistent error handling and reporting.
    """
    def __init__(
        self, 
        message: str,
        details: dict[str, Any] | None = None
    ):
        self.message = message
        self.details = details or {}
        super().__init__(message)
    
    def __str__(self) -> str:
        """Human-readable string representation of the error."""
        return self.message


class MentalLLaMAConnectionError(MentalLLaMABaseException):
    """
    Exception raised when connection to MentalLLaMA service fails.
    
    This could be due to network issues, service unavailability, or
    other connection-related problems.
    """
    def __init__(
        self, 
        message: str,
        endpoint: str | None = None,
        details: dict[str, Any] | None = None
    ):
        self.endpoint = endpoint
        # Use provided details only; do not inject endpoint into details
        combined_details = details if details is not None else {}
        super().__init__(message, combined_details)
    
    def __str__(self) -> str:
        """Human-readable string representation including endpoint."""
        if self.endpoint:
            return f"{self.message} (endpoint: {self.endpoint})"
        return super().__str__()


class MentalLLaMAAuthenticationError(MentalLLaMABaseException):
    """
    Exception raised when authentication with MentalLLaMA fails.
    
    This could be due to invalid API keys, expired credentials, or 
    insufficient permissions.
    """
    def __init__(
        self, 
        message: str,
        details: dict[str, Any] | None = None
    ):
        super().__init__(message, details)


class MentalLLaMAInferenceError(MentalLLaMABaseException):
    """
    Exception raised when MentalLLaMA inference process fails.
    
    This could be due to model-specific issues, invalid inputs, or
    unexpected errors during the inference process.
    """
    def __init__(
        self,
        message: str,
        model: str | None = None,
        details: dict[str, Any] | None = None
    ):
        # Store model identifier
        self.model = model
        # Use provided details or default to empty
        combined_details = details if details is not None else {}
        super().__init__(message, combined_details)

    def __str__(self) -> str:
        """Human-readable string including model information."""
        if self.model:
            return f"{self.message} (model: {self.model})"
        return super().__str__()


class MentalLLaMAValidationError(MentalLLaMABaseException):
    """
    Exception raised when input validation for MentalLLaMA fails.
    
    This could be due to invalid input formats, missing required fields,
    or input values outside of acceptable ranges.
    """
    def __init__(
        self, 
        message: str,
        validation_errors: dict[str, str] | None = None,
        details: dict[str, Any] | None = None
    ):
        self.validation_errors = validation_errors or {}
        
        # Only use explicit details; do not inject validation_errors into details
        combined_details = details if details is not None else {}
            
        super().__init__(message, combined_details)
    
    def __str__(self) -> str:
        """Human-readable string including validation errors."""
        base = super().__str__()
        if self.validation_errors:
            errors = ", ".join(f"{field}: {err}" for field, err in self.validation_errors.items())
            return f"{base} [{errors}]"
        return base


class MentalLLaMAQuotaExceededError(MentalLLaMABaseException):
    """
    Exception raised when API usage quota is exceeded.
    
    This occurs when the user has exceeded their allocated usage limits
    for the MentalLLaMA service.
    """
    def __init__(
        self, 
        message: str,
        quota_limit: int | None = None,
        quota_used: int | None = None,
        details: dict[str, Any] | None = None
    ):
        # Store quota information
        self.quota_limit = quota_limit
        self.quota_used = quota_used
        # Compute remaining quota
        if quota_limit is not None and quota_used is not None:
            self.quota_remaining = max(0, quota_limit - quota_used)
        else:
            self.quota_remaining = None
        # Merge provided details with quota details
        combined_details = details or {}
        if quota_limit is not None:
            combined_details["quota_limit"] = quota_limit
        if quota_used is not None:
            combined_details["quota_used"] = quota_used
            combined_details["quota_remaining"] = self.quota_remaining
        super().__init__(message, combined_details)
    
    def __str__(self) -> str:
        """Human-readable string including quota information."""
        base = super().__str__()
        parts = []
        if self.quota_limit is not None:
            parts.append(str(self.quota_limit))
        if self.quota_used is not None:
            parts.append(str(self.quota_used))
        if parts:
            return f"{base} ({', '.join(parts)})"
        return base