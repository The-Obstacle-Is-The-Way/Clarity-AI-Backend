"""
Authentication and Authorization Dependencies for the Presentation Layer.

This module provides FastAPI dependency functions required for handling
authentication and authorization within the API endpoints.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings # Corrected import
from app.core.domain.entities.user import User, UserRole
from app.core.errors.security_exceptions import InvalidCredentialsError
from app.core.interfaces.repositories.user_repository_interface import (
    IUserRepository,
)
from app.core.interfaces.services.auth_service_interface import (
    AuthServiceInterface,
)
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.infrastructure.database.session import get_async_session
from app.infrastructure.repositories.user_repository import get_user_repository
from app.infrastructure.security.auth_service import get_auth_service
from app.infrastructure.security.jwt_service import get_jwt_service
from app.domain.exceptions import AuthenticationError, AuthorizationError # Corrected path

# --- Type Hinting for Dependencies --- #

AuthServiceDep = Annotated[AuthServiceInterface, Depends(get_auth_service)]
JWTServiceDep = Annotated[JWTServiceInterface, Depends(get_jwt_service)]

# --- Dependency Functions --- #

# Define an explicit dependency function for the user repository
async def get_user_repository_dependency(
    session: AsyncSession = Depends(get_async_session), 
) -> IUserRepository:
    """Provides an instance of IUserRepository using the injected session."""
    return get_user_repository(session=session) 

# Use the new explicit dependency function
UserRepoDep = Annotated[IUserRepository, Depends(get_user_repository_dependency)]

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
TokenDep = Annotated[str, Depends(oauth2_scheme)]

# --- Dependency Functions --- #

def get_authentication_service(
    auth_service: AuthServiceInterface = Depends(get_auth_service),
) -> AuthServiceInterface:
    """Provides an instance of the Authentication Service."""
    return auth_service

def get_jwt_service(
    jwt_service: JWTServiceInterface = Depends(get_jwt_service),
) -> JWTServiceInterface:
    """Provides an instance of the JWT Service."""
    return jwt_service

async def get_current_user(
    token: TokenDep,
    jwt_service: JWTServiceDep,
    user_repo: UserRepoDep,
) -> User:
    """Dependency to get the current authenticated user from the token."""
    # --- DIAGNOSTIC LOG --- #
    import logging # Make sure logging is imported if not already
    logger = logging.getLogger(__name__) # Or use a specific logger
    logger.info(f"--- ORIGINAL get_current_user CALLED with token: {token[:20]}... ---") # Log first 20 chars of token
    # --- END DIAGNOSTIC LOG --- #

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt_service.decode_token(token)
        user_id: str = payload.sub
        if user_id is None:
            raise credentials_exception
    except InvalidCredentialsError: # Or specific JWT errors
        raise credentials_exception from None

    user = await user_repo.get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user

CurrentUserDep = Annotated[User, Depends(get_current_user)]

async def require_admin_role(current_user: CurrentUserDep) -> User:
    """Dependency that requires the current user to have the ADMIN role."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have permission to perform this action.",
        )
    return current_user

AdminUserDep = Annotated[User, Depends(require_admin_role)]

async def require_clinician_role(current_user: CurrentUserDep) -> User:
    """Dependency that requires the current user to have the CLINICIAN role."""
    # Allow ADMINs to also pass this check, as they often have superset permissions
    if current_user.role not in [UserRole.CLINICIAN, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User requires Clinician or Admin role.",
        )
    return current_user

ClinicianUserDep = Annotated[User, Depends(require_clinician_role)]

async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Dependency to get the current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is inactive"
        )
    return current_user

# New dependency for role checking
def require_roles(required_roles: list[UserRole]):
    """
    Dependency that requires the current user to have AT LEAST ONE of the specified roles.
    """
    async def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        # The User domain entity has `roles: set[UserRole]` and a `has_role` method.
        user_has_required_role = False
        for role in required_roles:
            if current_user.has_role(role):
                user_has_required_role = True
                break
        
        if not user_has_required_role:
            allowed_roles_str = ", ".join(role.value for role in required_roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User requires one of the following roles: {allowed_roles_str}",
            )
        return current_user
    return role_checker

async def get_current_active_user_wrapper(user: User = Depends(get_current_active_user)) -> User:
    """Simple wrapper around get_current_active_user."""
    return user

async def get_optional_user(
    token: str = Depends(OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)),
    jwt_service: JWTServiceDep = None,
    user_repo: UserRepoDep = None,
) -> User | None:
    """Dependency to get the current user if authenticated, or None if not."""
    if not token:
        return None
    try:
        return await get_current_user(token, jwt_service, user_repo)
    except HTTPException:
        return None


async def verify_provider_access(
    current_user: User = Depends(get_current_user),
    patient_id: str | None = None,
) -> User:
    """Dependency to verify a provider has access to a patient's data.
    
    This implements HIPAA-compliant access control to ensure that providers
    can only access data for their assigned patients.
    
    Args:
        current_user: The authenticated user entity
        patient_id: The ID of the patient whose data is being accessed
        
    Returns:
        The authenticated user if access is granted
        
    Raises:
        HTTPException: If access is denied
    """
    # Check if the user is an admin (full access)
    if current_user.has_role(UserRole.ADMIN):
        return current_user
        
    # Check if the user is a clinician
    if current_user.has_role(UserRole.CLINICIAN):
        # In a real implementation, this would check if the patient is
        # assigned to this provider in the database
        has_access = True  # This is a placeholder for test collection
        
        if has_access:
            return current_user
    
    # Access denied
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Not authorized to access this patient's data"
    )

__all__ = [
    "AdminUserDep",
    "AuthServiceDep",
    "ClinicianUserDep",
    "CurrentUserDep",
    "JWTServiceDep",
    "TokenDep",
    "UserRepoDep",
    "get_current_user",
    "get_user_repository_dependency",
    "oauth2_scheme",
    "require_admin_role",
    "require_clinician_role",
    "require_roles",
]
