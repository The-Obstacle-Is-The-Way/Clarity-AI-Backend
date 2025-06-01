"""
Biometric service dependency provider.

This module provides dependency injection for the biometric service
following clean architecture principles and SOLID design patterns.
"""

from typing import Annotated

from fastapi import Depends

from typing import cast

from app.core.interfaces.services.biometric_service_interface import BiometricServiceInterface
from app.infrastructure.services.biometric.biometric_service import BiometricService


def get_biometric_service() -> BiometricServiceInterface:
    """
    Provide a BiometricService instance.
    
    This function serves as a FastAPI dependency that provides an implementation
    of the BiometricServiceInterface. It follows the Dependency Inversion Principle
    by depending on abstractions (the interface) rather than concrete implementations.
    
    Returns:
        An instance implementing BiometricServiceInterface
    """
    # In a production environment, this might involve retrieving configuration,
    # establishing database connections, or setting up other dependencies.
    return cast(BiometricServiceInterface, BiometricService())


# Type alias for use in FastAPI dependency injection
BiometricServiceDep = Annotated[BiometricServiceInterface, Depends(get_biometric_service)]
