"""
Biometric Alert-related Dependencies.

This module provides dependency functions for biometric alert components
following clean architecture principles with proper separation of concerns.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.repositories.alert_repository_interface import AlertRepositoryInterface
from app.core.interfaces.services.encryption_service_interface import EncryptionServiceInterface
from app.infrastructure.di.container import get_container
from app.infrastructure.repositories.alert_repository import AlertRepository
from app.presentation.api.dependencies.database import get_db, DatabaseSessionDep
from app.presentation.api.dependencies.repository import get_encryption_service


def get_alert_repository(
    db_session: DatabaseSessionDep,
    encryption_service: EncryptionServiceInterface = Depends(get_encryption_service)
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
