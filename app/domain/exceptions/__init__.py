"""
Exception classes for the application domain.

This module exports common exceptions used throughout the application.
"""

from app.domain.exceptions.base_exceptions import (
    BaseApplicationError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    IntegrationError,
    BusinessRuleError,
    ApplicationError,
    AuthorizationError,
    DomainError,
    InfrastructureError,
    NotFoundError,
    ResourceNotFoundError,
)

from app.domain.exceptions.persistence_exceptions import (
    PersistenceError,
    RepositoryError,
    EntityNotFoundError,
    DataIntegrityError,
    ConnectionError,
    TransactionError,
    MigrationError,
    QueryError,
    SerializationError,
)

from app.domain.exceptions.token_exceptions import (
    TokenException,
    InvalidTokenException,
    TokenExpiredException,
    TokenBlacklistedException,
    TokenGenerationException,
    MissingTokenException,
    # Aliases
    InvalidTokenError,
    TokenExpiredError,
    MissingTokenError,
)

from app.domain.exceptions.appointment_exceptions import (
    InvalidAppointmentStateError,
    InvalidAppointmentTimeError,
    AppointmentConflictError,
    AppointmentNotFoundError,
    AppointmentCancellationError,
    AppointmentReschedulingError,
)

from app.domain.exceptions.security_exceptions import (
    SecurityError,
    PHIAccessError,
    PermissionDeniedError,
    InvalidCredentialsError,
    AccountLockedError,
    AccountDisabledError,
    TooManyAttemptsError,
    InvalidSessionError,
    SessionExpiredError,
)

# For backward compatibility
DomainException = BaseApplicationError
DomainError = BaseApplicationError

# Export all exceptions
__all__ = [
    # Base exceptions
    "BaseApplicationError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "ConfigurationError",
    "IntegrationError",
    "BusinessRuleError",
    "ApplicationError",
    "AuthorizationError",
    "DomainError",
    "InfrastructureError",
    "NotFoundError",
    "ResourceNotFoundError",
    
    # Persistence exceptions
    "PersistenceError",
    "RepositoryError", 
    "EntityNotFoundError",
    "DataIntegrityError",
    "ConnectionError",
    "TransactionError",
    "MigrationError",
    "QueryError",
    "SerializationError",
    
    # Token exceptions
    "TokenException",
    "InvalidTokenException",
    "TokenExpiredException",
    "TokenBlacklistedException",
    "TokenGenerationException",
    "MissingTokenException",
    "InvalidTokenError",
    "TokenExpiredError",
    "MissingTokenError",
    
    # Appointment exceptions
    "InvalidAppointmentStateError",
    "InvalidAppointmentTimeError",
    "AppointmentConflictError",
    "AppointmentNotFoundError",
    "AppointmentCancellationError",
    "AppointmentReschedulingError",
    
    # Security exceptions
    "SecurityError",
    "PHIAccessError",
    "PermissionDeniedError",
    "InvalidCredentialsError",
    "AccountLockedError",
    "AccountDisabledError",
    "TooManyAttemptsError",
    "InvalidSessionError",
    "SessionExpiredError",
    
    # Backward compatibility
    "DomainException",
    "DomainError",
]