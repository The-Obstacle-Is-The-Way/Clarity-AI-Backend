"""
Authentication service provider.

This module provides a single source of truth for authentication services
following clean architecture principles. It implements dependency injection
patterns ensuring testability and HIPAA compliance.
"""

from functools import lru_cache
from typing import Dict, Any, Optional

from fastapi import Depends
from fastapi.security import HTTPBearer

from app.core.config.settings import Settings, get_settings
from app.core.interfaces.services.authentication_service import IAuthenticationService
from app.infrastructure.security.jwt_service import get_jwt_service, JWTService
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.core.dependencies.database import get_db_session
from app.domain.entities.user import User
from app.domain.exceptions import AuthenticationError, EntityNotFoundError
from app.infrastructure.logging.logger import get_logger

# Security scheme for swagger docs
security = HTTPBearer()
logger = get_logger(__name__)

class AuthenticationService(IAuthenticationService):
    """
    Service responsible for user authentication logic.

    This service handles all authentication-related operations including
    user verification, token generation, and access control, ensuring
    HIPAA compliance throughout the authentication flow.
    """

    def __init__(
        self,
        user_repository,
        password_handler,
        jwt_service,
    ):
        """
        Initialize the AuthenticationService.

        Args:
            user_repository: Repository for user data access.
            password_handler: Handler for password hashing and verification.
            jwt_service: Service for JWT token creation and validation.
        """
        self.user_repository = user_repository
        self.password_handler = password_handler
        self.jwt_service = jwt_service
        logger.info("AuthenticationService initialized with dependencies")

    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate a user with username and password.

        Args:
            username: The user's username
            password: The user's plaintext password

        Returns:
            User entity if authentication successful, None otherwise

        Raises:
            AuthenticationError: For specific authentication issues
        """
        try:
            # Get user from repository
            user_model = await self.user_repository.get_by_username(username)

            if not user_model:
                logger.warning(f"Authentication failed: User {username} not found")
                raise AuthenticationError("Invalid username or password")

            # Check if user is active
            if not user_model.is_active:
                logger.warning(f"Authentication failed: User {username} is inactive")
                raise AuthenticationError("Account is inactive")

            # Verify password
            if not self.password_handler.verify_password(password, user_model.password):
                logger.warning(f"Authentication failed: Invalid password for user {username}")
                raise AuthenticationError("Invalid username or password")

            # Map to domain entity and return
            user = self._map_user_model_to_domain(user_model)
            logger.info(f"User {username} authenticated successfully")
            return user

        except Exception as e:
            logger.error(f"Error during authentication: {str(e)}")
            raise AuthenticationError("Authentication failed") from e

    async def get_user_by_id(self, user_id: str) -> User:
        """
        Get a user by their ID.

        Args:
            user_id: User's unique identifier

        Returns:
            User domain entity

        Raises:
            EntityNotFoundError: If user not found
        """
        try:
            user_model = await self.user_repository.get_by_id(user_id)
            if not user_model:
                raise EntityNotFoundError(f"User with ID {user_id} not found")
            return self._map_user_model_to_domain(user_model)
        except Exception as e:
            logger.error(f"Error retrieving user by ID: {str(e)}")
            raise

    def _map_user_model_to_domain(self, user_model) -> User:
        """Map data model to domain entity."""
        # Implement mapping logic based on your domain model
        return User(
            id=str(user_model.id),
            username=user_model.username,
            email=user_model.email,
            is_active=user_model.is_active,
            roles=[role.name for role in user_model.roles]
        )

    def create_access_token(self, user: User) -> str:
        """
        Create an access token for a user.

        Args:
            user: User domain entity

        Returns:
            JWT access token
        """
        data = {
            "sub": str(user.id),
            "roles": user.roles,
            "username": user.username
        }
        return self.jwt_service.create_access_token(data)

    def create_refresh_token(self, user: User) -> str:
        """
        Create a refresh token for a user.

        Args:
            user: User domain entity

        Returns:
            JWT refresh token
        """
        data = {
            "sub": str(user.id),
            "type": "refresh"
        }
        return self.jwt_service.create_refresh_token(data)

    def create_token_pair(self, user: User) -> Dict[str, str]:
        """
        Create both access and refresh tokens.

        Args:
            user: User domain entity

        Returns:
            Dictionary with access_token and refresh_token
        """
        return {
            "access_token": self.create_access_token(user),
            "refresh_token": self.create_refresh_token(user),
            "token_type": "bearer"
        }

    def refresh_token(self, refresh_token: str) -> Dict[str, str]:
        """
        Create a new access token using a refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            Dictionary with new access_token and existing refresh_token
        """
        # Verify the refresh token
        payload = self.jwt_service.verify_token(refresh_token)

        # Check if it's a refresh token
        if payload.get("type") != "refresh":
            raise AuthenticationError("Invalid refresh token")

        # Get user ID from token
        user_id = payload.get("sub")
        if not user_id:
            raise AuthenticationError("Invalid token payload")

        # Create a new access token
        data = {
            "sub": user_id,
            "roles": payload.get("roles", [])
        }

        return {
            "access_token": self.jwt_service.create_access_token(data),
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

@lru_cache
async def get_auth_service(
    settings: Settings = Depends(get_settings),
) -> IAuthenticationService:
    """
    Get an instance of the authentication service with proper dependencies.

    This factory function creates an authentication service with
    the necessary dependencies injected, following clean architecture
    principles for proper separation of concerns.

    Args:
        settings: Application settings

    Returns:
        An initialized authentication service
    """
    # Create dependencies
    jwt_service = await get_jwt_service(settings)
    user_repository = SQLAlchemyUserRepository(get_db_session())
    password_handler = PasswordHandler()

    # Create and return the service
    return AuthenticationService(
        user_repository=user_repository,
        password_handler=password_handler,
        jwt_service=jwt_service,
    )
