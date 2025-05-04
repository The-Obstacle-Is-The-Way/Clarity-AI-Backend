"""
XGBoost ML Service Factory.
"""

import logging
from functools import lru_cache

from app.core.services.ml.xgboost.interface import XGBoostInterface

# Import all available implementations
from app.core.services.ml.xgboost.service import XGBoostService

# Import the mock implementation for testing
from app.infrastructure.services.mock_xgboost_service_v2 import MockXGBoostService

# Set up logging
logger = logging.getLogger(__name__)

# Registry of available implementations
_registry = {
    "aws": XGBoostService,  # Default AWS implementation
    "mock": MockXGBoostService,  # Mock implementation for testing
}

# Cache to avoid creating multiple instances unnecessarily
_instances = {}

def get_xgboost_service() -> XGBoostInterface:
    """
    Factory function to create an XGBoost service instance.
    
    Returns:
        XGBoostInterface: An instance of the XGBoost service
    """
    # In production, we typically want the AWS implementation
    # For testing, this can be overridden
    return create_xgboost_service(implementation_name="mock")

@lru_cache(maxsize=8)  # Cache instances to improve performance
def create_xgboost_service(
    implementation_name: str = "mock", 
    **kwargs
) -> XGBoostInterface:
    """
    Create an XGBoost service instance based on implementation name.
    
    Args:
        implementation_name: Name of the implementation to create ("aws", "mock")
        **kwargs: Additional configuration parameters for the service
        
    Returns:
        An implementation of XGBoostInterface
        
    Raises:
        ValueError: If the requested implementation is not registered
    """
    # Get implementation class from registry
    if implementation_name not in _registry:
        logger.warning(f"Unknown XGBoost implementation '{implementation_name}'. Using 'mock' instead.")
        implementation_name = "mock"
    
    # Get implementation class
    implementation_class = _registry[implementation_name]
    
    # Create and return instance
    logger.info(f"Creating XGBoost service instance using '{implementation_name}' implementation")
    
    # Use cached instance if it exists
    cache_key = f"{implementation_name}:{hash(frozenset(kwargs.items()))}" 
    if cache_key in _instances:
        return _instances[cache_key]
    
    # Create new instance
    instance = implementation_class(**kwargs)
    _instances[cache_key] = instance
    
    return instance

def register_implementation(name: str, implementation_class: type[XGBoostInterface]) -> None:
    """
    Register a new XGBoost service implementation.
    
    Args:
        name: Name to register the implementation under
        implementation_class: Class implementing XGBoostInterface
    """
    logger.info(f"Registering XGBoost implementation: {name}")
    _registry[name] = implementation_class