"""
Authentication service facade.

This module provides a clean facade for the authentication service
following SOLID principles and GOF patterns.
"""

from functools import lru_cache
from typing import Optional

from fastapi import Depends
from fastapi.security import HTTPBearer

from app.core.config.settings import Settings, get_settings
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.core.dependencies.database import get_db_session

# Security scheme for swagger docs
security = HTTPBearer()


@lru_cache
def get_auth_service(
    settings: Settings = Depends(get_settings),
) -> AuthenticationService:
    """
    Get an instance of the authentication service with proper dependencies.
    
    This factory function creates an authentication service with
    the necessary dependencies injected, following clean architecture
    principles for proper separation of concerns.
    
    Args:
        settings: Application settings
        
    Returns:
        An initialized authentication service
    """
    # Create dependencies
    jwt_service = JWTService(settings)
    user_repository = SQLAlchemyUserRepository(get_db_session())
    password_handler = PasswordHandler()
    
    # Create and return the service
    return AuthenticationService(
        user_repository=user_repository,
        password_handler=password_handler,
        jwt_service=jwt_service,
    )
