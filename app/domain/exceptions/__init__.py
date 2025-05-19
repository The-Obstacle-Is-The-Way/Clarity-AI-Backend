"""
Exception classes for the application domain.

This module exports common exceptions used throughout the application.
"""

from app.domain.exceptions.appointment_exceptions import (
    AppointmentCancellationError,
    AppointmentConflictError,
    AppointmentNotFoundError,
    AppointmentReschedulingError,
    InvalidAppointmentStateError,
    InvalidAppointmentTimeError,
)
from app.domain.exceptions.auth_exceptions import (
    AccountDisabledException,
    AccountLockedException,
    AuthenticationException,
    AuthorizationException,
    InsufficientPermissionsException,
    InvalidCredentialsException,
    MaxSessionsExceededException,
    RoleRequiredException,
    SessionExpiredException,
    UserAlreadyExistsException,
    UserNotFoundException,
)
from app.domain.exceptions.base_exceptions import (
    AuthenticationError,
    AuthorizationError,
    BaseApplicationError,
    BusinessRuleError,
    ConfigurationError,
    IntegrationError,
    ValidationError,
)
from app.domain.exceptions.data_exceptions import DataIntegrityError, DataNotFoundError
from app.domain.exceptions.persistence_exceptions import (
    EntityNotFoundError,
    PersistenceError,
    RepositoryError,
)
from app.domain.exceptions.security_exceptions import (
    AccountDisabledError,
    AccountLockedError,
    InvalidCredentialsError,
    InvalidSessionError,
    PermissionDeniedError,
    PHIAccessError,
    SecurityError,
    SessionExpiredError,
    TooManyAttemptsError,
)
from app.domain.exceptions.token_exceptions import (  # Aliases
    InvalidTokenError,
    InvalidTokenException,
    MissingTokenError,
    MissingTokenException,
    TokenBlacklistedException,
    TokenException,
    TokenExpiredError,
    TokenExpiredException,
    TokenGenerationException,
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
    # Persistence exceptions
    "EntityNotFoundError",
    "PersistenceError",
    "RepositoryError",
    # Data exceptions
    "DataIntegrityError",
    "DataNotFoundError",
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
    # Auth exceptions
    "AuthenticationException",
    "AuthorizationException",
    "InvalidCredentialsException",
    "AccountLockedException",
    "AccountDisabledException",
    "SessionExpiredException",
    "InsufficientPermissionsException",
    "RoleRequiredException",
    "MaxSessionsExceededException",
    "UserNotFoundException",
    "UserAlreadyExistsException",
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
