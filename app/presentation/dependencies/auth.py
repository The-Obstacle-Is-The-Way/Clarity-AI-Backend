# -*- coding: utf-8 -*-
"""
Authentication related dependencies.
"""

import logging
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# Domain/Infrastructure Services & Repositories
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.domain.repositories.user_repository import UserRepository
from app.core.config import settings # Added for JWT settings
from app.core.domain.entities.user import User # Added for get_current_user

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

# Dependency provider for PasswordHandler (assuming simple instantiation)
def get_password_handler() -> PasswordHandler:
    """Provides a PasswordHandler instance."""
    return PasswordHandler()

# Placeholder provider for UserRepository
# This should be replaced with a real provider that yields an actual implementation
# possibly depending on a database session (e.g., Depends(get_db_session))
async def get_user_repository() -> UserRepository:
    """Placeholder dependency provider for UserRepository."""
    # In a real application, this would return an instance of UserRepositoryImpl
    # For now, raise error or return a mock if needed outside tests.
    # Tests should override this provider.
    logger.warning("Using placeholder get_user_repository provider.")
    # Option 1: Raise error if called outside test override
    raise NotImplementedError("UserRepository implementation/provider not fully configured.")
    # Option 2: Return a basic mock (less safe, might hide issues)
    # from unittest.mock import AsyncMock
    # return AsyncMock(spec=UserRepository)

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
    token: str = Depends(oauth2_scheme),
    jwt_service: JWTService = Depends(get_jwt_service), # Now defined above
    user_repo: UserRepository = Depends(get_user_repository)
) -> User:
    """
    Dependency to get the current user based on the provided JWT token.
    Verifies the token and fetches the user from the repository.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        logger.debug("Attempting to decode token.")
        payload = jwt_service.decode_token(token)
        username: Optional[str] = payload.get("sub")
        if username is None:
            logger.warning("Token payload missing 'sub' (username).")
            raise credentials_exception
        logger.info(f"Token decoded successfully for user: {username}")

    except Exception as e: # Catching generic Exception as decode_token might raise various JWT errors
        logger.error(f"Token decoding failed: {e}")
        raise credentials_exception from e

    # In a real application using an ORM or DB session:
    # user = await user_repo.get_by_username(username=username)
    # For now, using placeholder logic - this WILL fail if get_user_repository isn't overridden
    try:
        logger.debug(f"Attempting to fetch user '{username}' from repository.")
        user = await user_repo.get_by_username(username=username) # Assumes get_by_username exists
        if user is None:
            logger.warning(f"User '{username}' not found in repository.")
            raise credentials_exception
        logger.info(f"Successfully retrieved user '{username}' from repository.")
        return user
    except NotImplementedError:
         logger.error("get_user_repository was not overridden, cannot fetch user.")
         raise credentials_exception # Or a 500 error, as this is a config issue
    except Exception as e:
        logger.error(f"Error fetching user '{username}' from repository: {e}")
        raise credentials_exception

# Note: get_jwt_service is likely already defined in jwt_service.py
# Note: get_user_repository needs to be defined, potentially in a repositories dependency file.
# For now, assume get_user_repository exists or will be mocked/overridden in tests. 