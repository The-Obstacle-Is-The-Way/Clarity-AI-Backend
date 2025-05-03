"""
Biometric service dependencies for v1 API endpoints.

This module provides dependency injection functions for biometric
and alert services required by the v1 API endpoints, following
clean architecture principles.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.services.biometric_service_interface import BiometricServiceInterface
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface
from app.infrastructure.di.provider import get_service_instance


def get_biometric_service() -> BiometricServiceInterface:
    """
    Dependency for injecting the biometric service.
    
    Returns:
        BiometricServiceInterface: Instance of the biometric service.
    """
    return get_service_instance(BiometricServiceInterface)


def get_alert_service() -> AlertServiceInterface:
    """
    Dependency for injecting the alert service.
    
    Returns:
        AlertServiceInterface: Instance of the alert service.
    """
    return get_service_instance(AlertServiceInterface)


# Type aliases for cleaner dependency annotations
BiometricServiceDep = Annotated[BiometricServiceInterface, Depends(get_biometric_service)]
AlertServiceDep = Annotated[AlertServiceInterface, Depends(get_alert_service)]