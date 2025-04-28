"""
Factory module for creating XGBoost service instances.

This module implements the Factory pattern for creating instances of the XGBoost service.
It provides a unified interface for creating appropriately configured XGBoost service
implementations based on environment and configuration.
"""

import os
import logging
from typing import Dict, Type, Optional, Any

from app.core.services.ml.xgboost.interface import XGBoostInterface
from app.core.services.ml.xgboost.exceptions import ConfigurationError
from app.infrastructure.aws.service_factory_provider import get_aws_service_factory


# Registry of available implementations
_implementations: Dict[str, Type[XGBoostInterface]] = {}

# Module logger
logger = logging.getLogger(__name__)


def register_implementation(name: str, implementation_class: Type[XGBoostInterface]) -> None:
    """
    Register an implementation with the factory.
    
    Args:
        name: Name to register the implementation under
        implementation_class: Implementation class to register
        
    Raises:
        ValueError: If the name is already registered
    """
    if name in _implementations:
        raise ValueError(f"Implementation '{name}' already registered")
    
    _implementations[name] = implementation_class
    logger.debug(f"Registered XGBoost implementation: {name}")


def create_xgboost_service(
    implementation_name: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> XGBoostInterface:
    """
    Create a new XGBoost service instance.
    
    Args:
        implementation_name: Name of the implementation to create, or None for auto-detection
        config: Optional configuration dictionary to initialize the service with
        
    Returns:
        A new XGBoost service instance
        
    Raises:
        ConfigurationError: If the implementation is not found
    """
    # Auto-detect implementation if not specified
    if implementation_name is None:
        # Check for explicit environment variable
        impl_env = os.environ.get("XGBOOST_IMPLEMENTATION", "").lower()
        if impl_env and impl_env in _implementations:
            implementation_name = impl_env
        # Fall back to "aws" for production, "mock" for test/development
        elif os.environ.get("TESTING", "").lower() in ("1", "true", "yes"):
            implementation_name = "mock"
        else:
            implementation_name = "aws"
    
    # Convert to lowercase for case-insensitive matching
    name = implementation_name.lower()
    
    # Check if implementation exists
    if name not in _implementations:
        available_implementations = ", ".join(_implementations.keys())
        raise ConfigurationError(
            f"XGBoost implementation '{name}' not found",
            field="implementation",
            value=name,
            details=f"Available implementations: {available_implementations}"
        )
    
    # Create the service instance
    implementation_class = _implementations[name]
    logger.debug(f"Creating XGBoost service: {name}")
    
    # For AWS implementation, provide the AWS service factory
    if name == "aws":
        # Import definitive AWS implementation
        from app.core.services.ml.xgboost.aws_service import AWSXGBoostService
        
        # Create service with AWS factory
        aws_factory = get_aws_service_factory()
        service = AWSXGBoostService(aws_service_factory=aws_factory)
    else:
        # Create other implementations directly
        service = implementation_class()
    
    return service


# Create a factory function that's compatible with FastAPI's dependency injection
def get_xgboost_service():
    """
    Factory function for use with FastAPI's dependency injection system.
    
    This function creates an appropriate XGBoostService implementation
    based on the current environment. It's designed to be used directly
    with FastAPI's Depends().
    
    Returns:
        A FastAPI dependency that resolves to an implementation of XGBoostInterface
    """
    from fastapi import Request, Depends
    import asyncio
    
    async def _get_service(request: Request) -> XGBoostInterface:
        # Check if an instance already exists in app state (e.g. for testing)
        if hasattr(request.app.state, "xgboost_service"):
            return request.app.state.xgboost_service
        
        # Default configuration for service initialization
        config = {
            "aws_region": os.environ.get("AWS_REGION", "us-east-1"),
            "endpoint_prefix": os.environ.get("XGBOOST_ENDPOINT_PREFIX", "xgboost-"),
            "bucket_name": os.environ.get("XGBOOST_BUCKET", "novamind-xgboost-data"),
            "dynamodb_table_name": os.environ.get("XGBOOST_DYNAMODB_TABLE", "xgboost-predictions"),
            "audit_table_name": os.environ.get("AUDIT_LOG_TABLE", "xgboost-audit"),
            "model_mappings": {
                "suicide": "suicide-risk",
                "readmission": "readmission-risk",
                "treatment_medication_ssri": "medication-ssri-response",
                "treatment_therapy_cbt": "therapy-cbt-response"
            }
        }
        
        # Create a new service instance
        service = create_xgboost_service(None, config)
        
        # Initialize the service asynchronously if it's not already initialized
        if not service.is_initialized:
            asyncio.create_task(service.initialize(config))
        
        return service
    
    return Depends(_get_service)


# Register default implementations
def _register_defaults() -> None:
    """Register default implementations."""
    
    # Import implementations here to avoid circular imports
    from app.core.services.ml.xgboost.aws_service import AWSXGBoostService
    from app.core.services.ml.xgboost.aws_compatibility import AWSXGBoostService as AWSXGBoostCompatService
    from app.core.services.ml.xgboost.mock import MockXGBoostService
    
    # Register implementations
    register_implementation("aws", AWSXGBoostService)
    register_implementation("aws_compat", AWSXGBoostCompatService)
    register_implementation("mock", MockXGBoostService)


# Register defaults on module import
_register_defaults()