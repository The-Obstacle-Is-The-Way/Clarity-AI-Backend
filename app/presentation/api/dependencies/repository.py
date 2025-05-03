"""
Repository dependencies for API routes.

This module provides FastAPI dependency functions for repository access,
following clean architecture principles with proper dependency injection patterns.
This is a compatibility module that re-exports from database.py.
"""

from fastapi import Depends
from typing import Callable, Type, TypeVar

from app.core.interfaces.services.encryption_service_interface import EncryptionServiceInterface
from app.infrastructure.security.encryption_service import EncryptionService
from app.infrastructure.di.container import get_container

# Re-export from database.py for backward compatibility
from app.presentation.api.dependencies.database import get_repository, DatabaseSessionDep

# Maintain backward compatibility with existing imports
get_repository_dependency = get_repository

T = TypeVar('T')


def get_encryption_service() -> EncryptionServiceInterface:
    """
    Get the encryption service instance.
    
    This dependency function provides access to the encryption service
    for API routes, ensuring HIPAA-compliant data protection.
    
    Returns:
        An instance of the encryption service
    """
    container = get_container()
    try:
        return container.get(EncryptionServiceInterface)
    except KeyError:
        # Lazily register if not already available
        service = EncryptionService()
        container.register(EncryptionServiceInterface, service)
        return service