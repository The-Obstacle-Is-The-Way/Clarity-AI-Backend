"""
Authentication related dependencies.
"""

import logging

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings  # Added for JWT settings
from app.domain.entities.user import User as DomainUser
from app.domain.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    # Add other relevant exceptions from this module if needed
    TokenExpiredError,
)
from app.domain.repositories.user_repository import UserRepository as UserRepositoryInterface
from app.infrastructure.database.session import get_db  # Assuming get_db provides AsyncSession
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
    UserRepository as SqlAlchemyUserRepositoryImpl,
)

# Domain/Infrastructure Services & Repositories
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.infrastructure.security.password.password_handler import PasswordHandler

logger = logging.getLogger(__name__)

# Dependency provider for PasswordHandler (assuming simple instantiation)
def get_password_handler() -> PasswordHandler:
    """Provides a PasswordHandler instance."""
    logger.debug("Resolving PasswordHandler dependency.")
    return PasswordHandler()

# Placeholder provider for UserRepository
# This should be replaced with a real provider that yields an actual implementation
# possibly depending on a database session (e.g., Depends(get_db_session))
async def get_user_repository(db: AsyncSession = Depends(get_db)) -> UserRepositoryInterface:
    """Provides an instance of the SQLAlchemy UserRepository implementation."""
    logger.debug("Resolving UserRepository dependency (SqlAlchemy).")
    # Return the imported implementation class
    return SqlAlchemyUserRepositoryImpl(session=db)

# Moved get_jwt_service definition BEFORE get_authentication_service and get_current_user
def get_jwt_service() -> JWTService:
    """
    Provides an instance of the JWTService.
    Assumes JWTService only requires settings based on the previous refactor.
    """
    logger.debug("Resolving JWTService dependency.")
    # In a real app, might read secrets from config or environment
    return JWTService(
        secret_key=settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
        access_token_expire_minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    )

# Dependency provider for AuthenticationService (depends on get_jwt_service)
def get_authentication_service(
    # Declare dependencies using Depends
    user_repo: UserRepositoryInterface = Depends(get_user_repository), # Use interface hint
    password_handler: PasswordHandler = Depends(get_password_handler),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> AuthenticationService:
    """Provides an instance of AuthenticationService with its dependencies resolved."""
    logger.debug("Resolving AuthenticationService dependency.")
    return AuthenticationService(
        user_repository=user_repo,
        password_handler=password_handler,
        jwt_service=jwt_service
    )

# Dependency to extract token from header
async def get_token_from_header(request: Request) -> str:
    """
    Extracts the Bearer token from the Authorization header.
    Raises HTTPException 401 if the header is missing or malformed.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        logger.debug("Authorization header missing.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    parts = auth_header.split()
    if parts[0].lower() != "bearer" or len(parts) != 2:
        logger.debug(f"Malformed Authorization header: {auth_header}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials: Malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = parts[1]
    logger.debug("Bearer token extracted successfully.")
    return token

# Dependency to get the current user from token (depends on get_jwt_service)
async def get_current_user(
    token: str = Depends(get_token_from_header), # Use new extractor
    auth_service: AuthenticationService = Depends(get_authentication_service)
) -> DomainUser: # Return DomainUser type
    """
    Dependency to get the current authenticated user based on the token.
    Uses AuthenticationService to validate the token and retrieve the user.
    Handles authentication errors by raising appropriate HTTPExceptions.
    """
    try:
        logger.debug("Attempting to validate token and retrieve user.")
        # Validate token and get user using the service
        user, _ = await auth_service.validate_token(token) # Ignoring permissions for now
        if user is None:
            # Should not happen if validate_token raises exceptions properly
            logger.error("validate_token returned None user without raising error.")
            raise AuthenticationError("User not found after token validation")
        
        logger.info(f"Token validated successfully for user ID: {user.id}")
        return user
    except TokenExpiredError:
        logger.info("Authentication failed: Token has expired.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired",
            headers={'WWW-Authenticate': 'Bearer error="invalid_token", error_description="The token has expired."'}
        )
    except InvalidTokenError as e:
        logger.warning(f"Authentication failed: Invalid token. Reason: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {e}",
            headers={'WWW-Authenticate': 'Bearer error="invalid_token", error_description="The token is invalid."'}
        )
    except AuthenticationError as e:
        # Includes cases like user not found, user inactive, etc., from AuthenticationService
        logger.warning(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {e}",
            headers={'WWW-Authenticate': 'Bearer error="invalid_grant", error_description="Authentication failed."'} # Consider error type
        )
    except Exception as e:
        # Catch unexpected errors during validation
        logger.error(f"Unexpected error during token validation/user retrieval: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred during authentication.",
        )

# --- Moved Role Requirement Dependencies Earlier --- 
def require_role(required_role: str): # Use simple string role for this version
    """Factory function to create a dependency that requires a specific user role."""
    async def role_checker(current_user: DomainUser = Depends(get_current_user)) -> DomainUser:
        # Adapt logic if current_user.roles is the primary source
        user_roles = getattr(current_user, 'roles', [])
        if not user_roles:
            # Fallback to primary role if roles list is empty or missing
            user_roles = [getattr(current_user, 'role', None)]
            
        if required_role not in user_roles:
            logger.warning(f"User {current_user.id} with roles {user_roles} tried accessing resource requiring {required_role}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Requires {required_role} role."
            )
        return current_user
    return role_checker

# Specific role requirement dependencies (defined after factory)
require_clinician = require_role("clinician")
require_admin = require_role("admin")
require_patient = require_role("patient")
# --- End Moved Role Requirement Dependencies --- 

# Note: get_jwt_service is likely already defined in jwt_service.py
# Note: get_user_repository needs to be defined, potentially in a repositories dependency file.
# For now, assume get_user_repository exists or will be mocked/overridden in tests. 

# Note: get_jwt_service is likely already defined in jwt_service.py
# Note: get_user_repository needs to be defined, potentially in a repositories dependency file.
# For now, assume get_user_repository exists or will be mocked/overridden in tests. 