"""
XGBoost Service module for the Concierge Psychiatry Platform.

This module provides machine learning capabilities using XGBoost models, 
specifically designed for psychiatric risk assessment, treatment response
prediction, and clinical outcome forecasting.

The module is designed following the Strategy pattern, with multiple
implementations (AWS, mock) that can be selected based on configuration.
"""

import logging
import os
from typing import Any, Dict, Optional

# Re-export implementations for direct access if needed
from app.core.services.ml.xgboost.aws import AWSXGBoostService

# Import enums for type information
from app.core.services.ml.xgboost.enums import (
    PredictionType,
    ResponseLevel,
    RiskLevel,
    TreatmentCategory,
)

# Re-export exceptions
from app.core.services.ml.xgboost.exceptions import (
    ConfigurationError,
    DataPrivacyError,
    ModelNotFoundError,
    PredictionError,
    ResourceNotFoundError,
    ServiceConnectionError,
    ValidationError,
    XGBoostServiceError,
)

# Re-export factory functions
from app.core.services.ml.xgboost.factory import (
    get_xgboost_service,
)

# Re-export interfaces and enums
from app.core.services.ml.xgboost.interface import (
    ModelType,
    XGBoostInterface,
)
from app.core.services.ml.xgboost.mock import MockXGBoostService

# Logger for this module
logger = logging.getLogger(__name__)


def create_xgboost_service_from_env() -> XGBoostInterface:
    """
    Create and initialize an XGBoost service instance using environment variables.

    This function examines environment variables with the XGBOOST_ prefix
    to determine which implementation to use and how to configure it.

    Environment variables:
        XGBOOST_IMPLEMENTATION: Implementation to use (aws, mock)
        XGBOOST_LOG_LEVEL: Log level (DEBUG, INFO, WARNING, ERROR)
        XGBOOST_PRIVACY_LEVEL: Privacy level (STANDARD, ENHANCED, MAXIMUM)

        # AWS-specific settings
        XGBOOST_AWS_REGION: AWS region
        XGBOOST_AWS_ENDPOINT_PREFIX: Prefix for SageMaker endpoints
        XGBOOST_AWS_BUCKET: S3 bucket name

        # Mock-specific settings
        XGBOOST_MOCK_DELAY_MS: Delay in milliseconds to simulate network latency

    Returns:
        Initialized XGBoost service instance

    Raises:
        ConfigurationError: If environment variables are missing or invalid
    """
    try:
        # Get implementation from environment, default to mock for development
        implementation = os.environ.get("XGBOOST_IMPLEMENTATION", "mock").lower()

        # Get common configuration
        log_level = os.environ.get("XGBOOST_LOG_LEVEL", "INFO")

        # Get privacy level
        privacy_level_str = os.environ.get("XGBOOST_PRIVACY_LEVEL", "STANDARD")
        try:
            privacy_level = PrivacyLevel[privacy_level_str]
        except KeyError:
            valid_levels = [level.name for level in PrivacyLevel]
            raise ConfigurationError(
                f"Invalid privacy level: {privacy_level_str}. Valid levels: {', '.join(valid_levels)}",
                field="XGBOOST_PRIVACY_LEVEL",
                value=privacy_level_str,
            )

        # Create service instance
        service = get_xgboost_service(implementation_name=implementation)

        # Initialize with implementation-specific configuration
        if implementation == "aws":
            # AWS-specific configuration
            aws_config = _get_aws_config_from_env()
            aws_config.update({"log_level": log_level, "privacy_level": privacy_level})
            service.initialize(aws_config)

        elif implementation == "mock":
            # Mock-specific configuration
            mock_config = _get_mock_config_from_env()
            mock_config.update({"log_level": log_level, "privacy_level": privacy_level})
            service.initialize(mock_config)

        else:
            # This should not happen since the factory validates the implementation
            raise ConfigurationError(
                f"Unsupported implementation: {implementation}",
                field="XGBOOST_IMPLEMENTATION",
                value=implementation,
            )

        logger.info(f"Created XGBoost service: {implementation}")
        return service

    except KeyError as e:
        # Missing environment variable
        logger.error(f"Missing environment variable: {e}")
        raise ConfigurationError(f"Missing environment variable: {e}", field=str(e)) from e

    except Exception as e:
        # Other errors
        logger.error(f"Failed to create XGBoost service: {e}")
        if isinstance(e, ConfigurationError):
            raise
        else:
            raise ConfigurationError(
                f"Failed to create XGBoost service: {e!s}", details=str(e)
            ) from e


def _get_aws_config_from_env() -> dict[str, Any]:
    """
    Get AWS configuration from environment variables.

    Returns:
        AWS configuration dictionary

    Raises:
        ConfigurationError: If required variables are missing
    """
    required_vars = [
        "XGBOOST_AWS_REGION",
        "XGBOOST_AWS_ENDPOINT_PREFIX",
        "XGBOOST_AWS_BUCKET",
    ]

    try:
        # Check required variables
        for var in required_vars:
            if var not in os.environ:
                raise ConfigurationError(f"Missing environment variable: {var}", field=var)

        # Create configuration dictionary
        config = {
            "region_name": os.environ["XGBOOST_AWS_REGION"],
            "endpoint_prefix": os.environ["XGBOOST_AWS_ENDPOINT_PREFIX"],
            "bucket_name": os.environ["XGBOOST_AWS_BUCKET"],
        }

        # Add optional model mappings if present
        model_mappings = {}
        for key, value in os.environ.items():
            if key.startswith("XGBOOST_AWS_MODEL_"):
                model_type = key[len("XGBOOST_AWS_MODEL_") :].lower().replace("_", "-")
                model_mappings[model_type] = value

        if model_mappings:
            config["model_mappings"] = model_mappings

        return config

    except KeyError as e:
        # This shouldn't happen due to the check above, but just in case
        logger.error(f"Missing environment variable: {e}")
        raise ConfigurationError(f"Missing environment variable: {e}", field=str(e)) from e


def _get_mock_config_from_env() -> dict[str, Any]:
    """
    Get mock configuration from environment variables.

    Returns:
        Mock configuration dictionary
    """
    config = {}

    # Mock delay (optional)
    mock_delay = os.environ.get("XGBOOST_MOCK_DELAY_MS")
    if mock_delay is not None:
        try:
            config["mock_delay_ms"] = int(mock_delay)
        except ValueError:
            logger.warning(f"Invalid XGBOOST_MOCK_DELAY_MS value: {mock_delay}")

    return config


# Alias for backward compatibility and convenience
get_xgboost_service = create_xgboost_service_from_env


# Initialize the module
def _initialize_module() -> None:
    """Initialize the XGBoost service module."""
    # Set up module-level logging
    logging.getLogger(__name__).setLevel(
        getattr(logging, os.environ.get("XGBOOST_LOG_LEVEL", "INFO"))
    )


# Initialize the module when it's imported
_initialize_module()
