"""
Biometric alert dependencies.

This module provides dependency injection for biometric alert related services.
"""

# pylint: disable=missing-module-docstring

from fastapi import Depends
from typing import cast
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.biometric_alert_rule_service import (
    BiometricAlertRuleService,
)
from app.core.dependencies.database import get_db_session
from app.core.interfaces.repositories.alert_repository_interface import (
    IAlertRepository,
)
from app.core.interfaces.repositories.biometric_rule_repository import (
    IBiometricRuleRepository,
)
from app.core.interfaces.repositories.template_repository_interface import (
    ITemplateRepository,
)
from app.core.interfaces.services.encryption_service_interface import (
    IEncryptionService,
)
from app.infrastructure.repositories.alert_repository import AlertRepository
from app.infrastructure.repositories.memory.biometric_alert_template_repository import (
    InMemoryBiometricAlertTemplateRepository,
)
from app.infrastructure.repositories.sqlalchemy.biometric_alert_repository import (
    BiometricAlertRepository,
)
from app.infrastructure.repositories.sqlalchemy.biometric_alert_rule_repository import (
    SQLAlchemyBiometricAlertRuleRepository as BiometricRuleRepository,
)
from app.presentation.api.dependencies.repository import get_encryption_service


async def get_alert_repository(
    db_session: AsyncSession = Depends(get_db_session),
    encryption_service: IEncryptionService = Depends(get_encryption_service),
) -> IAlertRepository:
    """
    Dependency provider for alert repository.

    Args:
        db_session: Database session
        encryption_service: Encryption service for sensitive data

    Returns:
        Alert repository instance
    """
    return AlertRepository(db_session, encryption_service)


async def get_biometric_repository(
    db_session: AsyncSession = Depends(get_db_session),
    encryption_service: IEncryptionService = Depends(get_encryption_service),
) -> BiometricAlertRepository:
    """
    Dependency provider for biometric repository.

    Args:
        db_session: Database session
        encryption_service: Encryption service for sensitive data

    Returns:
        Biometric repository instance
    """
    return BiometricAlertRepository(db_session=db_session, encryption_service=encryption_service)


async def get_rule_repository(
    db_session: AsyncSession = Depends(get_db_session),
    encryption_service: IEncryptionService = Depends(get_encryption_service),
) -> IBiometricRuleRepository:
    """
    Dependency provider for biometric alert rule repository.

    Args:
        db_session: Database session
        encryption_service: Encryption service for sensitive data

    Returns:
        Biometric rule repository instance
    """
    return BiometricRuleRepository(db_session=db_session)


async def get_template_repository(
    db_session: AsyncSession = Depends(get_db_session),
) -> ITemplateRepository:
    """
    Get the biometric alert template repository instance.

    Args:
        db_session: Database session dependency

    Returns:
        An instance of the template repository
    """
    return InMemoryBiometricAlertTemplateRepository()


# Dependency for the BiometricEventProcessor
async def get_event_processor(
    alert_repo: IAlertRepository = Depends(get_alert_repository),
    biometric_repo: BiometricAlertRepository = Depends(get_biometric_repository),
    rule_repo: IBiometricRuleRepository = Depends(get_rule_repository),
    # Add template_repo: BiometricAlertTemplateRepositoryInterface = Depends(get_template_repository) when implemented
) -> None:
    # logger.warning("Using STUB implementation for get_event_processor")
    # In a real scenario, you would get/create the implementation here
    # from app.infrastructure.processors.biometric_event_processor import ConcreteEventProcessor
    # processor = ConcreteEventProcessor(alert_repo, biometric_repo, rule_repo, template_repo)
    # return processor
    return None  # Return None or raise NotImplementedError to prevent usage


async def get_biometric_alert_rule_service(
    rule_repository: IBiometricRuleRepository = Depends(get_rule_repository),
    template_repository: ITemplateRepository = Depends(get_template_repository),
) -> BiometricAlertRuleService:
    """
    Provides a BiometricAlertRuleService instance for dependency injection.

    Args:
        rule_repository: Repository for accessing biometric alert rules
        template_repository: Repository for accessing rule templates

    Returns:
        An instance of BiometricAlertRuleService
    """
    from app.infrastructure.repositories.sqlalchemy.biometric_alert_rule_repository import (
        SQLAlchemyBiometricAlertRuleRepository as ConcreteRuleRepo,
    )
    from app.infrastructure.repositories.memory.biometric_alert_template_repository import (
        InMemoryBiometricAlertTemplateRepository as ConcreteTemplateRepo,
    )

    concrete_rule_repo = cast(ConcreteRuleRepo, rule_repository)
    concrete_template_repo = cast(ConcreteTemplateRepo, template_repository)

    return BiometricAlertRuleService(  # type: ignore[arg-type]
        rule_repository=concrete_rule_repo,
        template_repository=concrete_template_repo,
    )
