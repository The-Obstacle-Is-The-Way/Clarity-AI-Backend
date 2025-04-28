# -*- coding: utf-8 -*-
"""
Core exceptions package.

This package contains all exceptions used throughout the application.
"""

from app.core.exceptions.base_exceptions import (
    ApplicationError,
    AuthenticationException,
    AuthorizationException,
    AuthorizationError,
    BaseException,
    BusinessRuleException,
    ConfigurationError,
    DatabaseException,
    ExternalServiceException,
    InitializationError,
    InvalidConfigurationError,
    PersistenceError,
    ResourceNotFoundException,
    ResourceNotFoundError,
    SecurityException,
    ValidationException,
    ValidationError,
    HIPAAComplianceError,
    ServiceProviderError,
    AnalysisError,
    EmbeddingError,
    IntegrationError,
)


from app.core.exceptions.ml_exceptions import (
    InvalidRequestError,
    MLServiceError,
    ModelNotFoundError,
    ServiceUnavailableError,
    PHIDetectionError,
    MentalLLaMAServiceError,
    MentalLLaMAInferenceError,
    XGBoostServiceError,
    DigitalTwinError,
)

__all__ = [
    "ApplicationError",
    "AuthenticationException",
    "AuthorizationException",
    "AuthorizationError",
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
    "PersistenceError",
    "PHIDetectionError",
    "ResourceNotFoundException",
    "ResourceNotFoundError",
    "SecurityException",
    "ServiceUnavailableError",
    "ServiceProviderError",
    "ValidationException",
    "ValidationError",
    "XGBoostServiceError",
    "AnalysisError",
]