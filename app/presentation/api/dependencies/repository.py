"""
Repository dependencies for API routes.

This module provides FastAPI dependency functions for repository access,
following clean architecture principles with proper dependency injection patterns.
This is a compatibility module that re-exports from database.py.
"""

from typing import TypeVar

from app.core.interfaces.services.encryption_service_interface import (
    IEncryptionService,
)
from app.infrastructure.di.container import get_container
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService

# Re-export from database.py for backward compatibility
from app.presentation.api.dependencies.database import DatabaseSessionDep, get_repository

# Maintain backward compatibility with existing imports
get_repository_dependency = get_repository

T = TypeVar('T')


def get_encryption_service() -> IEncryptionService:
    """
    Get the encryption service instance.
    
    This dependency function provides access to the encryption service
    for API routes, ensuring HIPAA-compliant data protection.
    
    Returns:
        An instance of the encryption service
    """
    container = get_container()
    try:
        return container.get(IEncryptionService)
    except KeyError:
        # Lazily register if not already available
        service = BaseEncryptionService()
        container.register(IEncryptionService, service)
        return service


def get_patient_repository(db_session: DatabaseSessionDep):
    """
    Get the patient repository instance.
    
    This dependency function provides access to the patient repository
    for working with patient data in a HIPAA-compliant manner.
    Patient data is encrypted at rest and in transit.
    
    Args:
        db_session: Database session dependency
        
    Returns:
        An instance of the patient repository
    """
    from app.core.interfaces.repositories.patient_repository_interface import IPatientRepository
    from app.infrastructure.repositories.patient_repository import PatientRepository
    
    # Use container to get or create repository
    container = get_container()
    try:
        return container.get(IPatientRepository)
    except KeyError:
        # Get encryption service for HIPAA compliance
        encryption_service = get_encryption_service()
        
        # Create repository with proper dependencies
        repo = PatientRepository(db_session, encryption_service)
        container.register(IPatientRepository, repo)
        return repo