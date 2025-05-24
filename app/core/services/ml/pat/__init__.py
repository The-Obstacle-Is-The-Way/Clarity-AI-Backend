"""
Patient Assessment Tool (PAT) Package.

This package provides a service for patient assessments and clinical evaluations.
"""

from app.core.services.ml.pat.bedrock import BedrockPAT
from app.core.services.ml.pat.exceptions import (
    AnalysisError,
    AnalysisNotFoundError,
    AuthorizationError,
    ConfigurationError,
    DataPrivacyError,
    EmbeddingError,
    InitializationError,
    IntegrationError,
    PATServiceError,
    ResourceNotFoundError,
    ServiceConnectionError,
    ValidationError,
)
from app.core.services.ml.pat.factory import PATServiceFactory
from app.core.services.ml.pat.mock import MockPATService
from app.core.services.ml.pat.pat_interface import PATInterface

__all__ = [
    "AnalysisError",
    "AnalysisNotFoundError",
    "AuthorizationError",
    # Implementations
    "BedrockPAT",
    "ConfigurationError",
    "DataPrivacyError",
    "EmbeddingError",
    "InitializationError",
    "IntegrationError",
    # Mock implementations for testing
    "MockPATService",
    # Interfaces
    "PATInterface",
    # Exceptions
    "PATServiceError",
    # Factory
    "PATServiceFactory",
    "ResourceNotFoundError",
    "ServiceConnectionError",
    "ValidationError",
]
