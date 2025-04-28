"""
Domain exceptions package.

This package contains all exception classes for the domain layer.
"""

from app.domain.exceptions.base import DomainException
from app.domain.exceptions.repository import (
    RepositoryException,
    EntityNotFoundException,
    DuplicateEntityException,
    DatabaseConnectionException,
    TransactionException,
    RepositoryError
)
from app.domain.exceptions.token_exceptions import (
    TokenException,
    InvalidTokenException,
    TokenExpiredException,
    TokenBlacklistedException,
    TokenGenerationException,
    MissingTokenException
)

# Aliases for backward compatibility
InvalidTokenError = InvalidTokenException
TokenExpiredError = TokenExpiredException
MissingTokenError = MissingTokenException
DomainError = DomainException

# Auth exceptions needed by the existing code
class AuthenticationError(DomainException):
    """Exception raised for authentication failures."""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message)

class AuthorizationError(DomainException):
    """Exception raised when a user is not authorized to access a resource."""
    def __init__(self, message: str = "Not authorized to perform this action"):
        super().__init__(message)

class EntityNotFoundError(DomainException):
    """Exception raised when an entity is not found."""
    def __init__(self, message: str = "Entity not found"):
        super().__init__(message)

class PermissionDeniedError(DomainException):
    """Exception raised when a user lacks required permissions."""
    def __init__(self, message: str = "Permission denied"):
        super().__init__(message)

class ValidationError(DomainException):
    """Exception raised for validation errors."""
    def __init__(self, message: str = "Validation error"):
        super().__init__(message)

class InvalidAppointmentStateError(ValidationError):
    """Exception raised for invalid appointment state transitions."""
    def __init__(self, message: str = "Invalid appointment state transition"):
        super().__init__(message)

class InvalidAppointmentTimeError(ValidationError):
    """Exception raised for invalid appointment times (e.g., past date)."""
    def __init__(self, message: str = "Invalid appointment time"):
        super().__init__(message)

class AppointmentConflictError(ValidationError):
    """Raised when attempting to create or move an appointment that conflicts with an existing one."""
    def __init__(self, message: str = "The requested appointment time conflicts with an existing appointment"):
        super().__init__(message)

class PHIAccessError(AuthorizationError):
    """Exception raised specifically for unauthorized attempts to access PHI."""
    def __init__(self, message: str = "Unauthorized access to Protected Health Information (PHI)"):
        super().__init__(message)

class SecurityError(DomainException):
    """General exception for security-related errors."""
    def __init__(self, message: str = "A security error occurred"):
        super().__init__(message)

__all__ = [
    # Base exceptions
    "DomainException",
    
    # Repository exceptions
    "RepositoryException",
    "EntityNotFoundException",
    "DuplicateEntityException", 
    "DatabaseConnectionException",
    "TransactionException",
    "RepositoryError",
    
    # Token exceptions
    "TokenException",
    "InvalidTokenException",
    "TokenExpiredException",
    "TokenBlacklistedException",
    "TokenGenerationException",
    "MissingTokenException",
    
    # Backward compatibility aliases
    "InvalidTokenError",
    "TokenExpiredError",
    "MissingTokenError",
    "DomainError",
    
    # Auth exceptions
    "AuthenticationError",
    "AuthorizationError",
    "EntityNotFoundError",
    "PermissionDeniedError",
    "ValidationError",
    
    # Appointment exceptions
    "InvalidAppointmentStateError",
    "InvalidAppointmentTimeError",
    "AppointmentConflictError",
    
    # PHI specific
    "PHIAccessError",
    
    # General Security
    "SecurityError"
]