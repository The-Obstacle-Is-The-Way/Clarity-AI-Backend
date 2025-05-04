"""
Biometric service dependencies for v1 API endpoints.

This module provides dependency injection functions for biometric
and alert services required by the v1 API endpoints, following
clean architecture principles.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.repositories.rule_repository_interface import RuleRepositoryInterface
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface
from app.core.interfaces.services.biometric_service_interface import BiometricServiceInterface
from app.infrastructure.di.provider import get_service_instance


def get_biometric_service() -> BiometricServiceInterface:
    """
    Dependency for injecting the biometric service.
    
    Returns:
        BiometricServiceInterface: Instance of the biometric service.
    """
    return get_service_instance(BiometricServiceInterface)


def get_alert_service() -> AlertServiceInterface:
    """Dependency injector for AlertServiceInterface."""
    return get_service_instance(AlertServiceInterface)


def get_rule_repository() -> RuleRepositoryInterface:
    """Dependency injector for RuleRepositoryInterface."""
    return get_service_instance(RuleRepositoryInterface)


# Type aliases for cleaner dependency annotations
BiometricServiceDep = Annotated[BiometricServiceInterface, Depends(get_biometric_service)]
AlertServiceDep = Annotated[AlertServiceInterface, Depends(get_alert_service)]