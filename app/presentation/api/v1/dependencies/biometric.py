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
from app.core.interfaces.services.biometric_service_interface import (
    BiometricServiceInterface,
)
from app.core.interfaces.services.alert_rule_template_service_interface import (
    AlertRuleTemplateServiceInterface,
)
from app.domain.repositories.biometric_rule_repository import BiometricRuleRepository
from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)
from app.domain.repositories.biometric_alert_rule_repository import (
    BiometricAlertRuleRepository,
)
from app.infrastructure.di.provider import get_repository_instance, get_service_instance


def get_biometric_service() -> BiometricServiceInterface:
    """
    Dependency for injecting the biometric service.

    Returns:
        BiometricServiceInterface: Instance of the biometric service.
    """
    from app.infrastructure.di.container import get_container

    return get_container().get(BiometricServiceInterface)


def get_alert_service() -> AlertServiceInterface:
    """Dependency injector for AlertServiceInterface."""
    from app.infrastructure.di.container import get_container

    return get_container().get(AlertServiceInterface)


def get_alert_rule_template_service(
    session: AsyncSession = Depends(get_db_session),
) -> AlertRuleTemplateServiceInterface:
    """
    Dependency injector for AlertRuleTemplateServiceInterface.

    Args:
        session: Database session for repository instances

    Returns:
        AlertRuleTemplateServiceInterface: Configured service with repositories
    """
    from app.application.services.alert_rule_template_service import (
        AlertRuleTemplateService,
    )
    from app.infrastructure.di.container import get_container

    # Get container
    container = get_container()

    # Try to get the service if already registered
    try:
        return container.get(AlertRuleTemplateServiceInterface)
    except KeyError:
        # Get repositories using the provided session
        template_repo = get_repository_instance(
            BiometricAlertTemplateRepository, session
        )
        rule_repo = get_repository_instance(BiometricAlertRuleRepository, session)

        # Create and return the service with proper repositories
        return AlertRuleTemplateService(template_repo, rule_repo)


def get_biometric_rule_repository(
    session: AsyncSession = Depends(get_db_session),
) -> BiometricRuleRepository:
    """Dependency injector for BiometricRuleRepository."""
    # Use the correct provider for repositories requiring a session
    from app.infrastructure.di.container import get_container

    factory = get_container().get_repository_factory(BiometricRuleRepository)
    return factory(session)


def get_biometric_alert_template_repository(
    session: AsyncSession = Depends(get_db_session),
) -> BiometricAlertTemplateRepository:
    """Dependency injector for BiometricAlertTemplateRepository."""
    from app.infrastructure.di.container import get_container

    factory = get_container().get_repository_factory(BiometricAlertTemplateRepository)
    return factory(session)


# Type aliases for cleaner dependency annotations
BiometricServiceDep = Annotated[
    BiometricServiceInterface, Depends(get_biometric_service)
]
AlertServiceDep = Annotated[AlertServiceInterface, Depends(get_alert_service)]
AlertRuleTemplateServiceDep = Annotated[
    AlertRuleTemplateServiceInterface, Depends(get_alert_rule_template_service)
]
BiometricRuleRepoDep = Annotated[
    BiometricRuleRepository, Depends(get_biometric_rule_repository)
]
BiometricAlertTemplateRepoDep = Annotated[
    BiometricAlertTemplateRepository, Depends(get_biometric_alert_template_repository)
]
