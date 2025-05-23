"""JWT Token Service Implementation.

This module provides an implementation of the ITokenService interface
using JWT (JSON Web Tokens) with HIPAA-compliant security measures.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pydantic import SecretStr

from app.core.config import settings
from app.domain.entities.user import User
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenBlacklistedException,
    TokenExpiredException,
    TokenGenerationException,
)
from app.domain.interfaces.token_service import ITokenService
from app.infrastructure.persistence.repositories.token_blacklist_repository import (
    TokenBlacklistRepository,
)


class JWTTokenService(ITokenService):
    """JWT implementation of the token service interface with HIPAA compliance."""

    def __init__(self, token_blacklist_repository: TokenBlacklistRepository):
        """
        Initialize the JWT token service.

        Args:
            token_blacklist_repository: Repository for managing token blacklist
        """
        self.token_blacklist_repository = token_blacklist_repository
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        self.algorithm = settings.JWT_ALGORITHM
        # Extract secret value from SecretStr for JWT operations
        self.secret_key = (
            settings.JWT_SECRET_KEY.get_secret_value()
            if isinstance(settings.JWT_SECRET_KEY, SecretStr)
            else settings.JWT_SECRET_KEY
        )

    def generate_tokens(self, user: User) -> dict[str, str]:
        """
        Generate access and refresh tokens for a user.

        Args:
            user: The user entity to generate tokens for

        Returns:
            Dictionary containing access_token and refresh_token

        Raises:
            TokenGenerationException: If token generation fails
        """
        try:
            # Create payload for access token
            access_token_expires = datetime.now(timezone.utc) + timedelta(
                minutes=self.access_token_expire_minutes
            )
            access_token_payload = {
                "sub": str(user.id),
                "email": user.email,
                # Only include role if it exists on the user entity
                **({"role": getattr(user, "role", "user")} if hasattr(user, "role") else {}),
                "exp": access_token_expires,
                "type": "access",
            }

            # Create payload for refresh token
            refresh_token_expires = datetime.now(timezone.utc) + timedelta(
                days=self.refresh_token_expire_days
            )
            refresh_token_payload = {
                "sub": str(user.id),
                "exp": refresh_token_expires,
                "type": "refresh",
            }

            # Generate tokens
            access_token = jwt.encode(
                access_token_payload, self.secret_key, algorithm=self.algorithm
            )
            refresh_token = jwt.encode(
                refresh_token_payload, self.secret_key, algorithm=self.algorithm
            )

            return {"access_token": access_token, "refresh_token": refresh_token}
        except Exception as e:
            raise TokenGenerationException(f"Failed to generate tokens: {e!s}")

    async def validate_access_token(self, token: str) -> dict[str, Any]:
        """
        Validate an access token and return its payload.

        Args:
            token: The access token to validate

        Returns:
            The decoded token payload

        Raises:
            InvalidTokenException: If token is invalid or malformed
            TokenExpiredException: If token has expired
            TokenBlacklistedException: If token has been blacklisted
        """
        try:
            # Check if token is blacklisted
            is_blacklisted = await self.token_blacklist_repository.is_blacklisted(token)
            if is_blacklisted:
                raise TokenBlacklistedException()

            # Decode the token
            payload: dict[str, Any] = jwt.decode(
                token, self.secret_key, algorithms=[self.algorithm]
            )

            # Verify token type
            if payload.get("type") != "access":
                raise InvalidTokenException("Invalid token type")

            return payload
        except jwt.ExpiredSignatureError:
            raise TokenExpiredException()
        except jwt.InvalidTokenError:
            raise InvalidTokenException()
        except Exception as e:
            raise InvalidTokenException(f"Token validation failed: {e!s}")

    async def validate_refresh_token(self, token: str) -> dict[str, Any]:
        """
        Validate a refresh token and return its payload.

        Args:
            token: The refresh token to validate

        Returns:
            The decoded token payload

        Raises:
            InvalidTokenException: If token is invalid or malformed
            TokenExpiredException: If token has expired
            TokenBlacklistedException: If token has been blacklisted
        """
        try:
            # Check if token is blacklisted
            is_blacklisted = await self.token_blacklist_repository.is_blacklisted(token)
            if is_blacklisted:
                raise TokenBlacklistedException()

            # Decode the token
            payload: dict[str, Any] = jwt.decode(
                token, self.secret_key, algorithms=[self.algorithm]
            )

            # Verify token type
            if payload.get("type") != "refresh":
                raise InvalidTokenException("Invalid token type")

            return payload
        except jwt.ExpiredSignatureError:
            raise TokenExpiredException()
        except jwt.InvalidTokenError:
            raise InvalidTokenException()
        except Exception as e:
            raise InvalidTokenException(f"Token validation failed: {e!s}")

    async def refresh_tokens(self, refresh_token: str, user: User) -> dict[str, str]:
        """
        Generate new access and refresh tokens using a valid refresh token.

        Args:
            refresh_token: The refresh token to validate
            user: The user entity to generate new tokens for

        Returns:
            Dictionary containing new access_token and refresh_token

        Raises:
            InvalidTokenException: If token is invalid or malformed
            TokenExpiredException: If token has expired
            TokenBlacklistedException: If token has been blacklisted
            TokenGenerationException: If token generation fails
        """
        # Validate the refresh token
        await self.validate_refresh_token(refresh_token)

        # Revoke the old refresh token
        await self.revoke_token(refresh_token)

        # Generate new tokens
        return self.generate_tokens(user)

    async def revoke_token(self, token: str) -> None:
        """
        Revoke (blacklist) a token.

        Args:
            token: The token to revoke

        Raises:
            InvalidTokenException: If token is invalid or malformed
        """
        try:
            # Decode the token without verification to get the expiration
            payload = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = payload.get("exp")

            if not exp_timestamp:
                raise InvalidTokenException("Token has no expiration")

            # Add token to blacklist
            expiry = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            await self.token_blacklist_repository.blacklist_token(token, expiry)
        except Exception as e:
            raise InvalidTokenException(f"Failed to revoke token: {e!s}")

    async def revoke_user_tokens(self, user_id: str) -> None:
        """
        Revoke all tokens for a specific user.

        Args:
            user_id: The ID of the user whose tokens to revoke
        """
        await self.token_blacklist_repository.blacklist_user_tokens(user_id)

    async def get_user_from_token(self, token: str) -> dict[str, Any]:
        """
        Extract and return the user information from a token.

        Args:
            token: The token to extract user information from

        Returns:
            Dictionary containing user information from the token

        Raises:
            InvalidTokenException: If token is invalid or malformed
            TokenExpiredException: If token has expired
            TokenBlacklistedException: If token has been blacklisted
        """
        payload = await self.validate_access_token(token)

        # Extract user information with safe defaults
        user_info: dict[str, Any] = {
            "id": payload.get("sub"),
            "email": payload.get("email"),
        }

        # Only include role if present in token
        if "role" in payload:
            user_info["role"] = payload["role"]

        return user_info
