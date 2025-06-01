"""
Authentication Service Dependencies.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.security.password_handler_interface import IPasswordHandler
from app.core.interfaces.security.jwt_service_interface import IJwtService
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.domain.interfaces.user_repository import UserRepositoryInterface

from app.application.security.authentication_service import AuthenticationService

from app.presentation.api.dependencies.repositories import get_user_repository
from app.presentation.api.dependencies.security import get_password_handler, get_jwt_service
from app.presentation.api.dependencies.logging import get_audit_logger
from app.core.config.settings import get_settings


def get_auth_service(
    password_handler: IPasswordHandler = Depends(get_password_handler),
    user_repository: UserRepositoryInterface = Depends(get_user_repository),
    jwt_service: IJwtService = Depends(get_jwt_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger),
) -> AuthenticationService:
    """Dependency injector for AuthenticationService.

    Note: We return the concrete implementation type instead of the interface
    to prevent FastAPI dependency resolution errors.
    """
    # Direct instantiation is more predictable for FastAPI
    # This avoids issues with container resolution and interface type hints
    return AuthenticationService(
        user_repository=user_repository,
        jwt_service=jwt_service,
        password_service=password_handler,
        audit_logger=audit_logger,
        settings=get_settings()
    )


# Type hint for dependency injection using Annotated pattern
AuthServiceDep = Annotated[AuthenticationService, Depends(get_auth_service)]
