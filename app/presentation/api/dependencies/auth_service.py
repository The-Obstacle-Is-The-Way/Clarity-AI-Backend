"""
Authentication Service Dependencies.
"""

from typing import Annotated

from fastapi import Depends

# Import concrete implementations - FastAPI can't handle interfaces as response types
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
    SQLAlchemyUserRepository,
)
from app.infrastructure.security.auth.authentication_service import (
    AuthenticationService,
)
from app.infrastructure.security.jwt.jwt_service import get_jwt_service
from app.infrastructure.security.jwt.jwt_service_impl import JWTServiceImpl
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.presentation.api.dependencies.repositories import get_user_repository
from app.presentation.api.dependencies.security import get_password_handler


def get_auth_service(
    password_handler: PasswordHandler = Depends(get_password_handler),
    user_repository: SQLAlchemyUserRepository = Depends(get_user_repository),
    jwt_service: JWTServiceImpl = Depends(get_jwt_service),
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
