"""
Biometric service dependencies for v1 API endpoints.

This module provides dependency injection functions for biometric
and alert services required by the v1 API endpoints, following
clean architecture principles.
"""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies.database import get_db_session
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface
from app.core.interfaces.services.biometric_service_interface import BiometricServiceInterface
from app.core.interfaces.services.alert_rule_template_service_interface import AlertRuleTemplateServiceInterface
from app.domain.repositories.biometric_rule_repository import BiometricRuleRepository
from app.domain.repositories.biometric_alert_template_repository import BiometricAlertTemplateRepository
from app.infrastructure.di.provider import get_repository_instance, get_service_instance


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


def get_alert_rule_template_service() -> AlertRuleTemplateServiceInterface:
    """Dependency injector for AlertRuleTemplateServiceInterface."""
    return get_service_instance(AlertRuleTemplateServiceInterface)


def get_biometric_rule_repository(
    session: AsyncSession = Depends(get_db_session),
) -> BiometricRuleRepository:
    """Dependency injector for BiometricRuleRepository."""
    # Use the correct provider for repositories requiring a session
    return get_repository_instance(BiometricRuleRepository, session)


def get_biometric_alert_template_repository(
    session: AsyncSession = Depends(get_db_session),
) -> BiometricAlertTemplateRepository:
    """Dependency injector for BiometricAlertTemplateRepository."""
    return get_repository_instance(BiometricAlertTemplateRepository, session)


# Type aliases for cleaner dependency annotations
BiometricServiceDep = Annotated[BiometricServiceInterface, Depends(get_biometric_service)]
AlertServiceDep = Annotated[AlertServiceInterface, Depends(get_alert_service)]
AlertRuleTemplateServiceDep = Annotated[AlertRuleTemplateServiceInterface, Depends(get_alert_rule_template_service)]
BiometricRuleRepoDep = Annotated[BiometricRuleRepository, Depends(get_biometric_rule_repository)]
BiometricAlertTemplateRepoDep = Annotated[BiometricAlertTemplateRepository, Depends(get_biometric_alert_template_repository)]
