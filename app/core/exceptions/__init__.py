"""
Core exceptions package.

This package contains all exceptions used throughout the application.
"""

# Base exceptions - canonical definitions
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

# JWT exceptions - specific implementations
from app.core.exceptions.jwt_exceptions import (
    JWTError,
    MissingTokenError,
)
from app.core.exceptions.jwt_exceptions import InvalidTokenError as JWTInvalidTokenError
from app.core.exceptions.jwt_exceptions import TokenExpiredError as JWTTokenExpiredError

# Data privacy exceptions
from app.core.exceptions.data_privacy import (
    DataPrivacyError,
)

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
    "AuthenticationException",
    "AuthorizationError",
    "AuthorizationException",
    "BaseException",
    "BusinessRuleException",
    "ConfigurationError",
    "DatabaseException",
    "EmbeddingError",
    "EntityNotFoundError",
    "ExternalServiceException",
    "HIPAAComplianceError",
    "InitializationError",
    "IntegrationError",
    "InvalidConfigurationError",
    "ModelExecutionError",
    "PersistenceError",
    "ResourceNotFoundError",
    "ResourceNotFoundException",
    "SecurityException",
    "ServiceProviderError",
    "ValidationError",
    "ValidationException",
    
    # Application errors
    "ApplicationError",
    "ErrorCode",
    
    # Auth exceptions
    "AuthenticationError",
    "AuthInvalidTokenError",
    "AuthTokenExpiredError",
    
    # JWT exceptions
    "JWTError",
    "MissingTokenError",
    "JWTInvalidTokenError",
    "JWTTokenExpiredError",
    
    # Data privacy
    "DataPrivacyError",
    
    # Security exceptions
    "InsufficientPermissionsError",
    "InvalidCredentialsError",
    "RateLimitExceededError",
    "SessionExpiredError",
    "TokenValidationError",
    "CoreSecurityException",
    "SecurityTokenExpiredError",
    
    # ML exceptions
    "DigitalTwinError",
    "InvalidRequestError",
    "MentalLLaMAInferenceError",
    "MentalLLaMAServiceError",
    "MLServiceError",
    "ModelNotFoundError",
    "PHIDetectionError",
    "PHISecurityError",
    "ServiceUnavailableError",
    "XGBoostServiceError",
]
