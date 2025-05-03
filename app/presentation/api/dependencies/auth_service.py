"""
Authentication Service Dependencies.

This module provides FastAPI dependency functions for authentication services,
following clean architecture principles with proper dependency injection patterns.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.infrastructure.di.container import get_container
from app.infrastructure.security.auth_service import AuthService, get_auth_service as get_core_auth_service


def get_auth_service_provider() -> AuthServiceInterface:
    """
    Provides an instance of the authentication service.
    
    This dependency function ensures proper dependency injection for authentication
    services in the presentation layer, maintaining clean architecture principles.
    
    Returns:
        An instance of the authentication service interface
    """
    # We can use the core implementation directly
    return get_core_auth_service()


# Type hinting for dependency injection
AuthServiceDep = Annotated[AuthServiceInterface, Depends(get_auth_service_provider)]
