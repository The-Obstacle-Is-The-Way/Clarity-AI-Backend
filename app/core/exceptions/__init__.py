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
)

# Application specific errors and codes
from app.core.exceptions.application_error import (
    ApplicationError,
    ErrorCode,
)

# JWT exceptions
from app.core.exceptions.jwt_exceptions import (
    JWTError,
    JWTExpiredError,
    JWTInvalidError,
    JWTMissingError,
)

# Auth exceptions
from app.core.exceptions.auth_exceptions import (
    InvalidCredentialsError,
    UserNotFoundError,
    UserAlreadyExistsError,
    UserInactiveError,
    PasswordMismatchError,
    PermissionDeniedError,
    RoleNotFoundError,
)

# Data privacy exceptions
from app.core.exceptions.data_privacy import (
    DataPrivacyException,
    PHIExposureRiskException,
    EncryptionError,
    DecryptionError,
)

# ML exceptions
from app.core.exceptions.ml_exceptions import (
    MLException,
    ModelLoadingError,
    PredictionError,
    InvalidInputFormatError,
    ModelTrainingError,
    ModelEvaluationError,
    FeatureExtractionError,
    ModelVersionError,
    ModelConfigurationError,
)

# Security errors from different modules
from app.core.errors.security_exceptions import (
    SecurityError,
    AccessDeniedError,
    AuthenticationFailedError,
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
    "JWTExpiredError",
    "JWTInvalidError",
    "JWTMissingError",
    "InvalidCredentialsError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "UserInactiveError",
    "PasswordMismatchError",
    "PermissionDeniedError",
    "RoleNotFoundError",
    "DataPrivacyException",
    "PHIExposureRiskException",
    "EncryptionError",
    "DecryptionError",
    "MLException",
    "ModelLoadingError",
    "PredictionError",
    "InvalidInputFormatError",
    "ModelTrainingError",
    "ModelEvaluationError",
    "FeatureExtractionError",
    "ModelVersionError",
    "ModelConfigurationError",
    "SecurityError",
    "AccessDeniedError",
    "AuthenticationFailedError",
]