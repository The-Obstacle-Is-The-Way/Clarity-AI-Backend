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
    "AccountDisabledError",
    "AccountDisabledException",
    "AccountLockedError",
    "AccountLockedException",
    "AppointmentCancellationError",
    "AppointmentConflictError",
    "AppointmentNotFoundError",
    "AppointmentReschedulingError",
    "AuthenticationError",
    # Auth exceptions
    "AuthenticationException",
    "AuthorizationError",
    "AuthorizationException",
    # Base exceptions
    "BaseApplicationError",
    "BusinessRuleError",
    "ConfigurationError",
    # Data exceptions
    "DataIntegrityError",
    "DataNotFoundError",
    "DomainError",
    # Backward compatibility
    "DomainException",
    # Persistence exceptions
    "EntityNotFoundError",
    "InsufficientPermissionsException",
    "IntegrationError",
    # Appointment exceptions
    "InvalidAppointmentStateError",
    "InvalidAppointmentTimeError",
    "InvalidCredentialsError",
    "InvalidCredentialsException",
    "InvalidSessionError",
    "InvalidTokenError",
    "InvalidTokenException",
    "MaxSessionsExceededException",
    "MissingTokenError",
    "MissingTokenException",
    "PHIAccessError",
    "PermissionDeniedError",
    "PersistenceError",
    "RepositoryError",
    "RoleRequiredException",
    # Security exceptions
    "SecurityError",
    "SessionExpiredError",
    "SessionExpiredException",
    "TokenBlacklistedException",
    # Token exceptions
    "TokenException",
    "TokenExpiredError",
    "TokenExpiredException",
    "TokenGenerationException",
    "TooManyAttemptsError",
    "UserAlreadyExistsException",
    "UserNotFoundException",
    "ValidationError",
]
