"""
JWT service dependency provider.

This module provides centralized dependency injection for JWT services
used throughout the application for authentication and authorization.
"""

from typing import Annotated

from fastapi import Depends, Request

from app.core.config.settings import get_settings
from app.core.interfaces.security.jwt_service_interface import IJwtService
from app.infrastructure.security.jwt import get_jwt_service
from app.infrastructure.security.jwt.jwt_service_impl import JWTServiceImpl
from app.presentation.api.dependencies.audit_logger import get_audit_logger
from app.presentation.api.dependencies.token_blacklist import get_token_blacklist_repository
from app.presentation.api.dependencies.user_repository import get_user_repository


def get_jwt_service_from_request(request: Request) -> IJwtService:
    """
    Provides a fully configured JWT service with all required dependencies.

    This function collects all necessary dependencies for the JWT service,
    including settings, repositories, and logging components.

    For testing, it checks if there's a JWT service override in the app state.

    Args:
        request: FastAPI request object

    Returns:
        An implementation of the IJwtService interface
    """
    # Check for test override first
    if hasattr(request.app.state, "jwt_service") and request.app.state.jwt_service:
        return request.app.state.jwt_service

    # Normal production path
    settings = get_settings()
    user_repository = get_user_repository()
    token_blacklist_repository = get_token_blacklist_repository()
    audit_logger = get_audit_logger()

    return get_jwt_service(
        settings=settings,
        user_repository=user_repository,
        token_blacklist_repository=token_blacklist_repository,
        audit_logger=audit_logger,
    )


# Type annotation for dependency injection
# Use concrete implementation for FastAPI compatibility while preserving
# clean architecture inside the application
JwtServiceDep = Annotated[JWTServiceImpl, Depends(get_jwt_service_from_request)]
