"""
Core exceptions package.

This package contains all exceptions used throughout the application.
"""

# Base exceptions - canonical definitions
# Security errors - specific implementations
from app.core.errors.security_exceptions import (
    InsufficientPermissionsError,
    InvalidCredentialsError,
    RateLimitExceededError,
    SessionExpiredError,
    TokenValidationError,
)
from app.core.errors.security_exceptions import SecurityException as CoreSecurityException
from app.core.errors.security_exceptions import TokenExpiredError as SecurityTokenExpiredError

# Application specific errors and codes
from app.core.exceptions.application_error import (
    ApplicationError,
    ErrorCode,
)

# Auth exceptions - specific implementations
from app.core.exceptions.auth_exceptions import (
    AuthenticationError,
)
from app.core.exceptions.auth_exceptions import InvalidTokenError as AuthInvalidTokenError
from app.core.exceptions.auth_exceptions import TokenExpiredError as AuthTokenExpiredError
from app.core.exceptions.base_exceptions import (
    AnalysisError,
    AuthenticationException,
    AuthorizationError,
    AuthorizationException,
    BaseException,
    BusinessRuleException,
    ConfigurationError,
    DatabaseException,
    EmbeddingError,
    EntityNotFoundError,
    ExternalServiceException,
    HIPAAComplianceError,
    InitializationError,
    IntegrationError,
    InvalidConfigurationError,
    ModelExecutionError,
    PersistenceError,
    ResourceNotFoundError,
    ResourceNotFoundException,
    SecurityException,
    ServiceProviderError,
    ValidationError,
    ValidationException,
)

# Data privacy exceptions
from app.core.exceptions.data_privacy import (
    DataPrivacyError,
)

# JWT exceptions - specific implementations
from app.core.exceptions.jwt_exceptions import InvalidTokenError as JWTInvalidTokenError
from app.core.exceptions.jwt_exceptions import (
    JWTError,
    MissingTokenError,
)
from app.core.exceptions.jwt_exceptions import TokenExpiredError as JWTTokenExpiredError

# ML exceptions
from app.core.exceptions.ml_exceptions import (
    DigitalTwinError,
    InvalidRequestError,
    MentalLLaMAInferenceError,
    MentalLLaMAServiceError,
    MLServiceError,
    ModelNotFoundError,
    PHIDetectionError,
    PHISecurityError,
    ServiceUnavailableError,
    XGBoostServiceError,
)

# Unified exports with aliases resolved
__all__ = [
    # Base exceptions
    "AnalysisError",
    # Application errors
    "ApplicationError",
    "AuthInvalidTokenError",
    "AuthTokenExpiredError",
    # Auth exceptions
    "AuthenticationError",
    "AuthenticationException",
    "AuthorizationError",
    "AuthorizationException",
    "BaseException",
    "BusinessRuleException",
    "ConfigurationError",
    "CoreSecurityException",
    # Data privacy
    "DataPrivacyError",
    "DatabaseException",
    # ML exceptions
    "DigitalTwinError",
    "EmbeddingError",
    "EntityNotFoundError",
    "ErrorCode",
    "ExternalServiceException",
    "HIPAAComplianceError",
    "InitializationError",
    # Security exceptions
    "InsufficientPermissionsError",
    "IntegrationError",
    "InvalidConfigurationError",
    "InvalidCredentialsError",
    "InvalidRequestError",
    # JWT exceptions
    "JWTError",
    "JWTInvalidTokenError",
    "JWTTokenExpiredError",
    "MLServiceError",
    "MentalLLaMAInferenceError",
    "MentalLLaMAServiceError",
    "MissingTokenError",
    "ModelExecutionError",
    "ModelNotFoundError",
    "PHIDetectionError",
    "PHISecurityError",
    "PersistenceError",
    "RateLimitExceededError",
    "ResourceNotFoundError",
    "ResourceNotFoundException",
    "SecurityException",
    "SecurityTokenExpiredError",
    "ServiceProviderError",
    "ServiceUnavailableError",
    "SessionExpiredError",
    "TokenValidationError",
    "ValidationError",
    "ValidationException",
    "XGBoostServiceError",
]
