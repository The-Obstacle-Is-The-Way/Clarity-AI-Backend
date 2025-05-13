"""
Core exceptions package.

This package contains all exceptions used throughout the application.
"""

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
    ExternalServiceException,
    HIPAAComplianceError,
    InitializationError,
    IntegrationError,
    InvalidConfigurationError,
    PersistenceError,
    ResourceNotFoundError,
    ResourceNotFoundException,
    SecurityException,
    ServiceProviderError,
    ValidationError,
    ValidationException,
)
from app.core.exceptions.ml_exceptions import (
    DigitalTwinError,
    InvalidRequestError,
    MentalLLaMAInferenceError,
    MentalLLaMAServiceError,
    MLServiceError,
    ModelNotFoundError,
    PHIDetectionError,
    ServiceUnavailableError,
    XGBoostServiceError,
    PHISecurityError,
)

# Application specific errors and codes
from app.core.exceptions.application_error import (
    ApplicationError,
    ErrorCode,
)

# JWT exceptions
from app.core.exceptions.jwt_exceptions import (
    JWTError,
    TokenExpiredError,
    InvalidTokenError,
    MissingTokenError,
)

# Auth exceptions
from app.core.exceptions.auth_exceptions import (
    AuthenticationError,
    AuthorizationError,
    TokenExpiredError,
    InvalidTokenError,
)

# Data privacy exceptions
from app.core.exceptions.data_privacy import (
    DataPrivacyError,
    # PHIExposureRiskException,
    # EncryptionError,
    # DecryptionError,
)

# Security errors from different modules
from app.core.errors.security_exceptions import (
    SecurityException,
    InvalidCredentialsError,
    TokenExpiredError as SecurityTokenExpiredError,
    TokenValidationError,
    InsufficientPermissionsError,
    SessionExpiredError,
    RateLimitExceededError,
)

__all__ = [
    "AnalysisError",
    "ApplicationError",
    "AuthenticationException",
    "AuthorizationError",
    "AuthorizationException",
    "BaseException",
    "BusinessRuleException",
    "ConfigurationError",
    "DatabaseException",
    "DigitalTwinError",
    "EmbeddingError",
    "EntityNotFoundError",
    "ExternalServiceException",
    "HIPAAComplianceError",
    "InitializationError",
    "IntegrationError",
    "InvalidConfigurationError",
    "InvalidRequestError",
    "MLServiceError",
    "MentalLLaMAInferenceError",
    "MentalLLaMAServiceError",
    "ModelNotFoundError",
    "PHIDetectionError",
    "PHISecurityError",
    "PersistenceError",
    "ResourceNotFoundError",
    "ResourceNotFoundException",
    "SecurityException",
    "ServiceProviderError",
    "ServiceUnavailableError",
    "ValidationError",
    "ValidationException",
    "XGBoostServiceError",
    "ErrorCode",
    "JWTError",
    "TokenExpiredError",
    "InvalidTokenError",
    "MissingTokenError",
    "AuthenticationError",
    "AuthorizationError",
    "DataPrivacyError",
    # "PHIExposureRiskException",
    # "EncryptionError",
    # "DecryptionError",
    "InvalidCredentialsError",
    "SecurityTokenExpiredError",
    "TokenValidationError",
    "InsufficientPermissionsError",
    "SessionExpiredError",
    "RateLimitExceededError",
]