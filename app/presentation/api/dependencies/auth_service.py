"""
Authentication Service Dependencies.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.infrastructure.di.container import get_container
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.presentation.api.dependencies.repositories import get_user_repository
from app.presentation.api.dependencies.security import get_password_handler


async def get_auth_service(
    password_handler: PasswordHandler = Depends(get_password_handler),
    user_repository: IUserRepository = Depends(get_user_repository),
) -> AuthServiceInterface:
    """Dependency injector for AuthenticationService."""
    container = get_container()
    # Use the correct class name here if needed for explicit resolution,
    # otherwise, rely on interface registration in the container.
    # Example direct instantiation (if not using container resolution):
    # return AuthenticationService(password_handler=password_handler, user_repository=user_repository)
    
    # Assuming the container resolves AuthServiceInterface to AuthenticationService:
    auth_service = container.resolve(AuthServiceInterface)
    return auth_service

# Type hinting for dependency injection
AuthServiceDep = Annotated[AuthServiceInterface, Depends(get_auth_service)]
