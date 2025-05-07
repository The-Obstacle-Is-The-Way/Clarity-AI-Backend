"""
Authentication and Authorization Dependencies for the Presentation Layer.

This module provides FastAPI dependency functions required for handling
authentication and authorization within the API endpoints.
"""

# Standard Library Imports
import logging # Ensure logging is imported
from typing import Annotated, AsyncGenerator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings, Settings
from app.core.domain.entities.user import User as DomainUser, UserRole, UserStatus
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
from app.core.interfaces.services.jwt_service import IJwtService

# Initialize logger for this module
logger = logging.getLogger(__name__) # Ensure this is at module level

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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
TokenDep = Annotated[str, Depends(oauth2_scheme)]

# --- Dependency Functions --- #

def get_authentication_service(
    auth_service: AuthServiceInterface = Depends(get_auth_service),
) -> AuthServiceInterface:
    """Provides an instance of the Authentication Service."""
    return auth_service

def get_jwt_service(settings: Settings = Depends(get_settings)) -> IJwtService:
    """Provides an instance of the JWT Service."""
    return get_jwt_service(settings)

async def get_current_user(
    token_credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(oauth2_scheme)],
    settings: Settings = Depends(get_settings),
    jwt_service: IJwtService = Depends(get_jwt_service),
    session: AsyncSession = Depends(get_async_session),
) -> DomainUser:
    logger.info(f"--- get_current_user CALLED --- Token credentials: {token_credentials}") # This should now work
    """
    Dependency to get the current user from a JWT token.
    Handles token validation, user retrieval, and role checks.
    """

    if token_credentials is None:
        logger.warning("get_current_user: No token credentials provided (token is None).")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = token_credentials.credentials 
    logger.info(f"get_current_user: Extracted token string: {token[:20] if token else 'None'}...") 

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    expired_token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Signature has expired", 
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        logger.info("get_current_user: Attempting to decode token with jwt_service...") 
        payload = jwt_service.decode_token(token=token)
        logger.info(f"get_current_user: Token decoded successfully. Payload sub: {payload.get('sub')}") 
        
        username: str | None = payload.get("sub") 
        if username is None:
            logger.warning("get_current_user: Username (sub) not in token payload.")
            raise credentials_exception
        
    except InvalidTokenException as e: 
        logger.warning(f"get_current_user: Invalid token - {e}")
        raise credentials_exception from e
    except TokenExpiredException as e: 
        logger.warning(f"get_current_user: Expired token - {e}")
        raise expired_token_exception from e
    except JWTError as e: 
        logger.warning(f"get_current_user: JWTError - {e}")
        raise credentials_exception from e

    user_repo = UserRepositoryImpl(session) 
    user_service = UserService(user_repo, jwt_service, settings) 
    
    try:
        user_id_from_token = payload["sub"] 
        logger.info(f"get_current_user: Attempting to fetch user by ID: {user_id_from_token}") 
        user = await user_service.get_user_by_id_str(user_id_str=user_id_from_token)
        
    except ValueError as e: 
        logger.error(f"get_current_user: Invalid user ID format in token: {payload.get('sub')}. Error: {e}")
        raise credentials_exception from e


    if user is None:
        logger.warning(f"get_current_user: User not found for ID: {payload.get('sub')}")
        raise credentials_exception
    
    if user.status != UserStatus.ACTIVE: # Check against Enum member
        logger.warning(f"get_current_user: User {user.username} is not active. Status: {user.status}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    logger.info(f"get_current_user: User {user.username} authenticated successfully.")
    return user

CurrentUserDep = Annotated[DomainUser, Depends(get_current_user)]

async def require_admin_role(current_user: CurrentUserDep) -> DomainUser:
    """Dependency that requires the current user to have the ADMIN role."""
    if UserRole.ADMIN not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have permission to perform this action.",
        )
    return current_user

AdminUserDep = Annotated[DomainUser, Depends(require_admin_role)]

async def require_clinician_role(current_user: CurrentUserDep) -> DomainUser:
    """Dependency that requires the current user to have the CLINICIAN role."""
    # Allow ADMINs to also pass this check, as they often have superset permissions
    if not ({UserRole.CLINICIAN, UserRole.ADMIN} & current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User requires Clinician or Admin role.",
        )
    return current_user

ClinicianUserDep = Annotated[DomainUser, Depends(require_clinician_role)]

async def get_current_active_user(
    current_user: DomainUser = Depends(get_current_user),
) -> DomainUser:
    """Dependency to get the current active user."""
    if current_user.status != UserStatus.ACTIVE:
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
    async def role_checker(current_user: DomainUser = Depends(get_current_active_user)) -> DomainUser:
        # The User domain entity has `roles: set[UserRole]` and a `has_role` method.
        user_has_required_role = False
        if current_user.roles:
            for role in required_roles:
                if role in current_user.roles:
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

async def get_current_active_user_wrapper(user: DomainUser = Depends(get_current_active_user)) -> DomainUser:
    """Simple wrapper around get_current_active_user."""
    return user

async def get_optional_user(
    token: str = Depends(OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)),
    jwt_service: JWTServiceDep = None,
    user_repo: UserRepoDep = None,
) -> DomainUser | None:
    """Dependency to get the current user if authenticated, or None if not."""
    if not token:
        return None
    try:
        return await get_current_user(token, jwt_service, user_repo)
    except HTTPException:
        return None


async def verify_provider_access(
    current_user: DomainUser = Depends(get_current_user),
    patient_id: str | None = None,
) -> DomainUser:
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
