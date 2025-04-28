# -*- coding: utf-8 -*-
"""
Authentication related dependencies.
"""

import logging
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer

# Domain/Infrastructure Services & Repositories
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.infrastructure.security.jwt.exceptions import TokenExpiredError, InvalidTokenError
from app.infrastructure.security.auth.exceptions import AuthenticationError
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SqlAlchemyUserRepository
from app.domain.repositories.user_repository import UserRepository
from app.core.config import settings # Added for JWT settings
from app.core.domain.entities.user import User # Added for get_current_user
from sqlalchemy.ext.asyncio import AsyncSession
from app.infrastructure.database.session import get_db # Assuming get_db provides AsyncSession

logger = logging.getLogger(__name__)

# Dependency provider for PasswordHandler (assuming simple instantiation)
def get_password_handler() -> PasswordHandler:
    """Provides a PasswordHandler instance."""
    logger.debug("Resolving PasswordHandler dependency.")
    return PasswordHandler()

# Placeholder provider for UserRepository
# This should be replaced with a real provider that yields an actual implementation
# possibly depending on a database session (e.g., Depends(get_db_session))
async def get_user_repository(db: AsyncSession = Depends(get_db)) -> UserRepository:
    """Provides an instance of SqlAlchemyUserRepository bound to the request's DB session."""
    logger.debug("Resolving UserRepository dependency (SqlAlchemy).")
    return SqlAlchemyUserRepository(session=db)

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
    user_repo: UserRepository = Depends(get_user_repository), 
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

# Dependency to get the current user from token (depends on get_jwt_service)
async def get_current_user(
    token: str = Depends(get_token_from_header), # Use new extractor
    auth_service: AuthenticationService = Depends(get_authentication_service)
) -> User:
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

# Note: get_jwt_service is likely already defined in jwt_service.py
# Note: get_user_repository needs to be defined, potentially in a repositories dependency file.
# For now, assume get_user_repository exists or will be mocked/overridden in tests. 

# Dependency to require admin privileges (using the factory)
require_admin = require_role("admin")

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

# Note: get_jwt_service is likely already defined in jwt_service.py
# Note: get_user_repository needs to be defined, potentially in a repositories dependency file.
# For now, assume get_user_repository exists or will be mocked/overridden in tests. 