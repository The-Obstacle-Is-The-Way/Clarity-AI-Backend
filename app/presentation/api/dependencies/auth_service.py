# -*- coding: utf-8 -*-
"""
Authentication Service Provider for FastAPI.

This module provides a clean dependency interface for the AuthenticationService,
ensuring proper handling of database connections and avoiding response model issues.
"""

from typing import Dict, Any, Optional, Callable, AsyncGenerator, Annotated, Type
from fastapi import Depends

# Use infrastructure implementation of user repository
from app.infrastructure.database.persistence.repositories.user_repository import UserRepository
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.presentation.api.dependencies.auth import get_jwt_service
from app.core.interfaces.repositories.user_repository import IUserRepository
from app.presentation.api.dependencies.user_repository import get_user_repository_provider
from app.infrastructure.di.container import container
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_session
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

# Create cached instance of password handler
_password_handler = PasswordHandler()

async def get_auth_service_provider(
    jwt_service: JWTService = Depends(get_jwt_service),
    db_session = Depends(get_db_session)
) -> AuthenticationService:
    """
    Provide a configured AuthenticationService instance with all dependencies.
    
    This function properly chains dependencies without exposing them directly 
    in a way that would confuse FastAPI's response model generation.
    
    Args:
        jwt_service: JWT service for token operations
        db_session: Database session (intentionally not type-annotated)
        
    Returns:
        Configured AuthenticationService instance
    """
    # Create user repository with the session
    user_repository = UserRepository(session=db_session)
    
    # Create and return authentication service
    auth_service = AuthenticationService(
        user_repository=user_repository,
        password_handler=_password_handler,
        jwt_service=jwt_service
    )
    
    return auth_service 