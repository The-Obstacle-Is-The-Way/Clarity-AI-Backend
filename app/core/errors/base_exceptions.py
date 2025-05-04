"""
Base exception classes for the application domain layer.

This module defines the base exception hierarchy following clean architecture
principles. All domain-specific exceptions should inherit from these base classes
to ensure consistent error handling across the application.
"""

from typing import Any


class BaseAppException(Exception):
    """
    Base exception class for all application-specific exceptions.
    
    This provides a standardized structure for error messages, error codes,
    and additional contextual information needed for proper error handling
    and reporting across all layers of the application.
    
    Attributes:
        message (str): Human-readable error message
        error_code (str): Optional machine-readable error code
        detail (dict): Optional additional contextual information
    """
    
    def __init__(self, 
                 message: str, 
                 error_code: str | None = None, 
                 detail: dict[str, Any] | None = None):
        """
        Initialize the base exception.
        
        Args:
            message: Human-readable error description
            error_code: Optional error code for programmatic handling
            detail: Optional dictionary with additional error context
        """
        self.message = message
        self.error_code = error_code
        self.detail = detail or {}
        super().__init__(self.message)
        
    def __str__(self) -> str:
        """Return the string representation of the exception."""
        if self.error_code:
            return f"{self.error_code}: {self.message}"
        return self.message


class DomainException(BaseAppException):
    """
    Base exception for domain-specific errors.
    
    These exceptions represent business rule violations and domain invariant
    failures, separate from technical or infrastructure concerns.
    """
    pass


class ValidationException(BaseAppException):
    """
    Base exception for data validation errors.
    
    Used when data fails to meet domain rules or constraints, making it
    unsuitable for processing by the domain logic.
    """
    pass


class NotFoundException(BaseAppException):
    """
    Exception raised when a requested entity cannot be found.
    
    This is used when attempting to access an entity (e.g., user, patient)
    that does not exist in the system.
    """
    def __init__(self, entity_type: str, identifier: Any, **kwargs):
        """
        Initialize not found exception with entity information.
        
        Args:
            entity_type: Type of entity that was not found
            identifier: The identifier that was used in the lookup
            **kwargs: Additional keyword arguments for the base class
        """
        message = f"{entity_type} with identifier '{identifier}' not found"
        detail = kwargs.pop('detail', {})
        detail.update({
            'entity_type': entity_type,
            'identifier': str(identifier)
        })
        super().__init__(message, detail=detail, **kwargs)


class InfrastructureException(BaseAppException):
    """
    Base exception for infrastructure layer errors.
    
    Used for errors related to external systems, databases, 
    network issues, etc., that are not directly related to domain logic.
    """
    pass