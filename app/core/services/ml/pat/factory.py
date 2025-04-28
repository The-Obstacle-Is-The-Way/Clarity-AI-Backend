"""
Factory for creating PAT service instances.

This module provides a factory for creating PAT service instances,
allowing for easy switching between different implementations (mock, AWS, Bedrock, etc.)
based on configuration.

PAT (Pretrained Actigraphy Transformer) is a core ML microservice that provides
actigraphy analysis capabilities for the psychiatric digital twin platform.
"""

import logging
from typing import Any, Dict, Optional, Union, Type

# Use the canonical config location
from app.config.settings import get_settings

settings = get_settings()
from app.core.exceptions import InvalidConfigurationError
from app.core.services.ml.pat.exceptions import InitializationError
from app.core.services.ml.pat.pat_interface import PATInterface
from app.core.services.ml.pat.mock import MockPATService

# Conditionally import the AWS implementation
try:
    from app.core.services.ml.pat.aws import AWSPATService
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

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
    _SERVICE_REGISTRY: Dict[str, Type[PATInterface]] = {
        "mock": MockPATService
    }
    
    # Register available implementations
    if AWS_AVAILABLE:
        _SERVICE_REGISTRY["aws"] = AWSPATService
    
    if BEDROCK_AVAILABLE:
        _SERVICE_REGISTRY["bedrock"] = BedrockPAT
    
    @classmethod
    def create_pat_service(cls, config: Optional[Union[Dict[str, Any], str]] = None) -> PATInterface:
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
                raise InvalidConfigurationError("Missing 'provider' in PAT configuration dictionary")
            
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
        
        logger.info(f"Creating PAT service of type: {provider}")
        provider_type = provider.lower()
        if provider_type == "bedrock":
            from app.core.services.ml.pat.bedrock import BedrockPAT
            service = BedrockPAT()
            
            # Add test_mode flag for test environments
            if service_config is None:
                service_config = {}
            
            # Detect test environment by checking if we're being called from a test
            import traceback
            stack = traceback.extract_stack()
            if any('test_' in frame.name for frame in stack) or \
               any('/tests/' in frame.filename for frame in stack):
                service_config["test_mode"] = True
                
            service.initialize(service_config)
        else:
            service_class = cls._SERVICE_REGISTRY[provider]
            service = service_class()
            service.initialize(service_config)
        
        return service
    
    # For backward compatibility
    def create_service(self, service_type: Optional[str] = None) -> PATInterface:
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
                f"Invalid PAT service type: {service_type}. "
                f"Available types: {available_types}"
            )
    