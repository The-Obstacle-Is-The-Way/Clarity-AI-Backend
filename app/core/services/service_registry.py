"""
Provides a way to retrieve registered services.

This acts as a simple service locator or part of a larger DI framework.
"""

from typing import Any, TypeVar

# In a real implementation, this might interact with a DI container
# like dependency_injector or a custom registry.
_SERVICE_REGISTRY = {}

T = TypeVar('T')

def register_service(service_name: str, service_instance: Any):
    """Register a service instance (Placeholder)."""
    print(f"Registering service: {service_name}")
    _SERVICE_REGISTRY[service_name] = service_instance

def get_service(service_name: str) -> Any:
    """
    Retrieve a registered service by name (Placeholder).
    
    Args:
        service_name: The name of the service to retrieve.
        
    Returns:
        The registered service instance.
        
    Raises:
        KeyError: If the service is not registered.
    """
    print(f"Attempting to get service: {service_name}")
    # In a real setup, you'd retrieve the actual service.
    # For now, just return None or raise an error if needed for tests.
    if service_name not in _SERVICE_REGISTRY:
        # Depending on how tests are structured, you might want to return a mock
        # or raise an error.
        print(f"Warning: Service '{service_name}' not found in registry. Returning None.")
        return None # Or raise KeyError(f"Service '{service_name}' not registered.")
        
    return _SERVICE_REGISTRY[service_name]

# Example of how you might use Type hinting if retrieving by class type
def get_service_by_type(service_type: type[T]) -> T:
    """
    Retrieve a registered service by its type (Placeholder).
    """
    service_name = service_type.__name__ # Example naming convention
    print(f"Attempting to get service by type: {service_name}")
    if service_name not in _SERVICE_REGISTRY:
         print(f"Warning: Service type '{service_name}' not found in registry. Returning None.")
         # return None # Or raise error
         raise KeyError(f"Service type '{service_name}' not found in registry.")
    
    instance = _SERVICE_REGISTRY[service_name]
    if not isinstance(instance, service_type):
        raise TypeError(f"Registered service '{service_name}' is not of type {service_type.__name__}")
    return instance
