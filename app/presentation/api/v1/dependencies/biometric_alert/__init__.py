"""
Biometric alert dependencies.

This module provides dependency injection for biometric alert related services.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.interfaces.repositories.alert_repository_interface import AlertRepositoryInterface
from app.core.interfaces.repositories.biometric_rule_repository import IBiometricRuleRepository
from app.core.interfaces.services.encryption_service_interface import EncryptionServiceInterface
# Corrected import path for AlertRepository
from app.infrastructure.repositories.alert_repository import AlertRepository
from app.infrastructure.repositories.sqlalchemy.biometric_alert_repository import ( 
    BiometricAlertRepository,
)
# Removed faulty import from non-existent endpoints.biometric_alert_rules
from app.infrastructure.repositories.sqlalchemy.biometric_alert_rule_repository import ( 
    BiometricRuleRepository,
)
from app.presentation.api.v1.dependencies.database import get_db_session
from app.presentation.api.v1.dependencies.security import get_encryption_service


async def get_alert_repository(
    db_session: AsyncSession = get_db_session,
    encryption_service: EncryptionServiceInterface = get_encryption_service
) -> AlertRepositoryInterface:
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
    db_session: AsyncSession = get_db_session,
    encryption_service: EncryptionServiceInterface = get_encryption_service
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
    db_session: AsyncSession = get_db_session
) -> IBiometricRuleRepository:
    """
    Dependency provider for biometric alert rule repository.
    
    Args:
        db_session: Database session
        
    Returns:
        Biometric rule repository instance
    """
    return BiometricRuleRepository(db_session=db_session)
