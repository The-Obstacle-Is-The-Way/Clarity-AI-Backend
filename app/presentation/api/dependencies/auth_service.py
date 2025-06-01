"""
Authentication Service Dependencies.
"""

from typing import Annotated

from fastapi import Depends

from app.infrastructure.security.password.password_handler import PasswordHandler
from app.domain.interfaces.user_repository import UserRepositoryInterface
from app.infrastructure.security.jwt.jwt_service import JWTService, get_jwt_service
from app.presentation.api.dependencies.repositories import get_user_repository
from app.presentation.api.dependencies.security import get_password_handler
from app.infrastructure.security.auth.authentication_service import (
    AuthenticationService,
)


def get_auth_service(
    password_handler: PasswordHandler = Depends(get_password_handler),
    user_repository: UserRepositoryInterface = Depends(get_user_repository),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> AuthenticationService:
    """Dependency injector for AuthenticationService.

    Note: We return the concrete implementation type instead of the interface
    to prevent FastAPI dependency resolution errors.
    """
    # Direct instantiation is more predictable for FastAPI
    # This avoids issues with container resolution and interface type hints
    return AuthenticationService(
        password_handler=password_handler,
        user_repository=user_repository,
        jwt_service=jwt_service,
    )


# Type hint for dependency injection using Annotated pattern
AuthServiceDep = Annotated[AuthenticationService, Depends(get_auth_service)]
