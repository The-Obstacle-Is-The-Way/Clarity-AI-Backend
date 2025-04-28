"""
Exception classes for the XGBoost service module.

This module defines custom exceptions that are raised by the XGBoost service
to provide clean error handling and meaningful error messages.
"""

from typing import Optional, Any, Dict


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
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to a dictionary for serialization.
        
        Returns:
            Dictionary representation of the exception
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            **self.details
        }


class ValidationError(XGBoostServiceError):
    """Exception raised when request validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None, **kwargs):
        """
        Initialize a validation error.
        
        Args:
            message: Error message
            field: Name of the field that failed validation
            value: Value that failed validation
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            field=field,
            value=value,
            **kwargs
        )


class DataPrivacyError(XGBoostServiceError):
    """Exception raised when PHI is detected in data."""
    
    def __init__(self, message: str, field: Optional[str] = None, phi_type: Optional[str] = None, **kwargs):
        """
        Initialize a data privacy error.
        
        Args:
            message: Error message
            field: Name of the field containing PHI
            phi_type: Type of PHI detected
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            field=field,
            phi_type=phi_type,
            **kwargs
        )


class ResourceNotFoundError(XGBoostServiceError):
    """Exception raised when a requested resource is not found."""
    
    def __init__(self, message: str, resource_type: Optional[str] = None, resource_id: Optional[str] = None, **kwargs):
        """
        Initialize a resource not found error.
        
        Args:
            message: Error message
            resource_type: Type of resource that was not found
            resource_id: ID of the resource that was not found
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            resource_type=resource_type,
            resource_id=resource_id,
            **kwargs
        )


class ModelNotFoundError(ResourceNotFoundError):
    """Exception raised when a requested ML model is not found."""
    
    def __init__(self, message: str, model_type: Optional[str] = None, model_version: Optional[str] = None, **kwargs):
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
            resource_id=f"{model_type}:{model_version}" if model_type and model_version else model_type,
            model_type=model_type,
            model_version=model_version,
            **kwargs
        )


class PredictionError(XGBoostServiceError):
    """Exception raised when a prediction fails."""
    
    def __init__(self, message: str, model_type: Optional[str] = None, cause: Optional[str] = None, **kwargs):
        """
        Initialize a prediction error.
        
        Args:
            message: Error message
            model_type: Type of model that failed
            cause: Cause of the failure
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            model_type=model_type,
            cause=cause,
            **kwargs
        )


class ServiceConnectionError(XGBoostServiceError):
    """Exception raised when a connection to an external service fails."""
    
    def __init__(self, message: str, service_name: Optional[str] = None, cause: Optional[str] = None, **kwargs):
        """
        Initialize a service connection error.
        
        Args:
            message: Error message
            service_name: Name of the service that failed
            cause: Cause of the failure
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            service_name=service_name,
            cause=cause,
            **kwargs
        )


class ConfigurationError(XGBoostServiceError):
    """Exception raised when there is a configuration error."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None, **kwargs):
        """
        Initialize a configuration error.
        
        Args:
            message: Error message
            field: Name of the field with an error
            value: Value that caused the error
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            field=field,
            value=value,
            **kwargs
        )


class ServiceConfigurationError(XGBoostServiceError):
    """Exception raised when there is a configuration error with an external service."""
    
    def __init__(self, message: str, service_name: Optional[str] = None, config_key: Optional[str] = None, **kwargs):
        """
        Initialize a service configuration error.
        
        Args:
            message: Error message
            service_name: Name of the service with configuration issues
            config_key: The configuration key that has issues
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            service_name=service_name,
            config_key=config_key,
            **kwargs
        )


class ServiceUnavailableError(XGBoostServiceError):
    """Exception raised when an external service is unavailable."""
    
    def __init__(self, message: str, service_name: Optional[str] = None, retry_after: Optional[int] = None, **kwargs):
        """
        Initialize a service unavailable error.
        
        Args:
            message: Error message
            service_name: Name of the unavailable service
            retry_after: Suggested time (in seconds) to wait before retrying
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            service_name=service_name,
            retry_after=retry_after,
            **kwargs
        )


class ThrottlingError(XGBoostServiceError):
    """Exception raised when requests are being throttled by an external service."""
    
    def __init__(self, message: str, service_name: Optional[str] = None, retry_after: Optional[int] = None, **kwargs):
        """
        Initialize a throttling error.
        
        Args:
            message: Error message
            service_name: Name of the service that is throttling requests
            retry_after: Suggested time (in seconds) to wait before retrying
            **kwargs: Additional error context
        """
        super().__init__(
            message,
            service_name=service_name,
            retry_after=retry_after,
            **kwargs
        )