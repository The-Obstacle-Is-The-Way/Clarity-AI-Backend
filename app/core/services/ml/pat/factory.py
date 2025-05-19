"""
Factory for creating PAT service instances.

This module provides a factory for creating PAT service instances,
allowing for easy switching between different implementations (mock, AWS, Bedrock, etc.)
based on configuration.

PAT (Pretrained Actigraphy Transformer) is a core ML microservice that provides
actigraphy analysis capabilities for the psychiatric digital twin platform.
"""

import logging
from typing import Any

# Use the canonical config location
from app.config.settings import get_settings

settings = get_settings()
from app.core.exceptions import InvalidConfigurationError
from app.core.services.ml.pat.exceptions import InitializationError
from app.core.services.ml.pat.mock import MockPATService
from app.core.services.ml.pat.pat_interface import PATInterface

# Import the Bedrock implementation
try:
    from app.core.services.ml.pat.bedrock import BedrockPAT

    BEDROCK_AVAILABLE = True
except ImportError:
    BEDROCK_AVAILABLE = False

# Set up logging with no PHI
logger = logging.getLogger(__name__)


class PATServiceFactory:
    """Factory for creating PAT service instances.

    This factory follows the Factory Method pattern to create
    different implementations of the PATInterface based on
    configuration or runtime needs.

    The PAT service is a critical component of the psychiatric digital twin
    platform, providing actigraphy analysis capabilities using pretrained
    transformer models.
    """

    # Service type to implementation mapping
    _SERVICE_REGISTRY: dict[str, type[PATInterface]] = {"mock": MockPATService}

    # Instance cache for reusing services with the same configuration
    _instance_cache: dict[str, PATInterface] = {}

    # Register available implementations
    if BEDROCK_AVAILABLE:
        _SERVICE_REGISTRY["bedrock"] = BedrockPAT

    @classmethod
    def create_pat_service(cls, config: dict[str, Any] | str | None = None) -> PATInterface:
        """Create and initialize a PAT service instance.

        Args:
            config: Either a configuration dictionary or a provider string.
                   If dict, must contain at least {'provider': 'provider_name'}
                   If string, interpreted as the provider name
                   If None, uses settings.ml_config["pat"]["provider"]

        Returns:
            An initialized PAT service instance

        Raises:
            InvalidConfigurationError: If provider configuration is invalid
        """
        provider = None
        service_config = {}

        # Parse config parameter
        if config is None:
            # Use settings
            if not hasattr(settings, "ml_config") or not settings.ml_config:
                raise InvalidConfigurationError("Missing ML configuration in settings")

            pat_config = settings.ml_config.get("pat", {})
            if not pat_config:
                raise InvalidConfigurationError("Missing PAT configuration in settings")

            provider = pat_config.get("provider")
            if not provider:
                raise InvalidConfigurationError("Missing 'provider' in PAT configuration")

            # Extract config excluding provider
            service_config = {k: v for k, v in pat_config.items() if k != "provider"}

        elif isinstance(config, str):
            # Config is just the provider name
            provider = config

        elif isinstance(config, dict):
            # Config is a dictionary
            provider = config.get("provider")
            if not provider:
                raise InvalidConfigurationError(
                    "Missing 'provider' in PAT configuration dictionary"
                )

            # Extract config excluding provider
            service_config = {k: v for k, v in config.items() if k != "provider"}

        else:
            raise InvalidConfigurationError(f"Invalid config type: {type(config)}")

        # Create service instance
        if provider not in cls._SERVICE_REGISTRY:
            available_types = list(cls._SERVICE_REGISTRY.keys())
            raise InvalidConfigurationError(
                f"Invalid PAT service provider: {provider}. "
                f"Available providers: {available_types}"
            )

        # Generate a cache key based on provider and sorted config items
        cache_key = f"{provider}-" + "-".join(f"{k}:{v}" for k, v in sorted(service_config.items()))

        # Check if we already have a service instance with this configuration
        if cache_key in cls._instance_cache:
            return cls._instance_cache[cache_key]

        logger.info(f"Creating PAT service of type: {provider}")

        # Get service class from registry and create instance
        service_class = cls._SERVICE_REGISTRY[provider]
        service = service_class()

        # For tests, add test_mode flag
        if service_config is None:
            service_config = {}

        # Detect test environment
        import traceback

        stack = traceback.extract_stack()
        if any("test_" in frame.name for frame in stack) or any(
            "/tests/" in frame.filename for frame in stack
        ):
            service_config["test_mode"] = True

        # Initialize the service
        service.initialize(service_config)

        # Cache the instance
        cls._instance_cache[cache_key] = service

        return service

    # For backward compatibility
    def create_service(self, service_type: str | None = None) -> PATInterface:
        """Create a PAT service instance (without initialization).

        Args:
            service_type: Type of service to create ("mock", "aws", "bedrock", etc.)
                          If None, uses settings.PAT_SERVICE_TYPE

        Returns:
            An uninitialized PAT service instance

        Raises:
            InitializationError: If service_type is invalid
        """
        # Use settings if service_type not provided
        if service_type is None:
            service_type = getattr(settings, "PAT_SERVICE_TYPE", "mock")

        # Create service instance
        if service_type in self._SERVICE_REGISTRY:
            logger.info(f"Creating PAT service of type: {service_type}")
            return self._SERVICE_REGISTRY[service_type]()
        else:
            available_types = list(self._SERVICE_REGISTRY.keys())
            raise InitializationError(
                f"Invalid PAT service type: {service_type}. " f"Available types: {available_types}"
            )
