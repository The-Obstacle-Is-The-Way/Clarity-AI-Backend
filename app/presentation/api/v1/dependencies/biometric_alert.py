"""
Biometric Alert-related Dependencies.

This module provides dependency functions for biometric alert components
following clean architecture principles with proper separation of concerns.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.biometric_alert_rule_service import (
    BiometricAlertRuleService,
)
from app.core.dependencies.database import get_db_session
from app.core.interfaces.repositories.alert_repository_interface import (
    AlertRepositoryInterface,
)
from app.core.interfaces.services.encryption_service_interface import (
    EncryptionServiceInterface,
)
from app.domain.repositories.biometric_alert_rule_repository import (
    BiometricAlertRuleRepository,
)
from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)
from app.infrastructure.di.container import get_container
from app.infrastructure.repositories.alert_repository import AlertRepository
from app.infrastructure.repositories.memory.biometric_alert_template_repository import (
    InMemoryBiometricAlertTemplateRepository,
)
from app.infrastructure.repositories.sqlalchemy.biometric_alert_rule_repository import (
    SQLAlchemyBiometricAlertRuleRepository,
)
from app.presentation.api.dependencies.database import get_db
from app.presentation.api.dependencies.repository import get_encryption_service


def get_alert_repository(
    db_session: AsyncSession = Depends(get_db_session),
    encryption_service: EncryptionServiceInterface = Depends(get_encryption_service),
) -> AlertRepositoryInterface:
    """
    Get the alert repository instance.

    This dependency function provides access to the alert repository
    for working with alert data in a HIPAA-compliant manner.
    Alert data is encrypted at rest and in transit.

    Args:
        db_session: Database session dependency
        encryption_service: Encryption service for HIPAA compliance

    Returns:
        An instance of the alert repository
    """
    # Use container to get or create repository
    container = get_container()
    try:
        return container.get(AlertRepositoryInterface)
    except KeyError:
        # Create repository with proper dependencies
        repo = AlertRepository(db_session, encryption_service)
        container.register(AlertRepositoryInterface, repo)
        return repo


async def get_biometric_alert_rule_repository(
    db: AsyncSession = Depends(get_db),
) -> BiometricAlertRuleRepository:
    """
    Get the biometric alert rule repository implementation.

    Args:
        db: Database session

    Returns:
        Implementation of BiometricAlertRuleRepository
    """
    return SQLAlchemyBiometricAlertRuleRepository(db)


async def get_biometric_alert_template_repository() -> BiometricAlertTemplateRepository:
    """
    Get the biometric alert template repository implementation.

    Returns:
        Implementation of BiometricAlertTemplateRepository
    """
    # Using in-memory implementation for now
    # In production, this would be replaced with a database-backed implementation
    return InMemoryBiometricAlertTemplateRepository()


async def get_biometric_alert_rule_service(
    rule_repository: BiometricAlertRuleRepository = Depends(get_biometric_alert_rule_repository),
    template_repository: BiometricAlertTemplateRepository = Depends(
        get_biometric_alert_template_repository
    ),
) -> BiometricAlertRuleService:
    """
    Get the biometric alert rule service.

    Args:
        rule_repository: Implementation of BiometricAlertRuleRepository
        template_repository: Implementation of BiometricAlertTemplateRepository

    Returns:
        Instance of BiometricAlertRuleService
    """
    return BiometricAlertRuleService(
        rule_repository=rule_repository, template_repository=template_repository
    )
