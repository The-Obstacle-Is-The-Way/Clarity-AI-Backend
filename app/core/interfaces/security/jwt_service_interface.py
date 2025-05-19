"""
JWT Service Interface.

This module defines the interface for JWT (JSON Web Token) operations, 
supporting authentication and authorization in the application
while maintaining HIPAA compliance and clean architecture.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional, Union
from uuid import UUID


class IJwtService(ABC):
    """
    Interface for JWT (JSON Web Token) service operations.

    This interface encapsulates the functionality required for:
    - Creating access and refresh tokens
    - Verifying and decoding tokens
    - Managing token blacklisting
    - Token identity operations

    Any concrete implementation must adhere to the methods
    defined in this interface, ensuring proper dependency inversion
    according to Clean Architecture principles.
    """

    @abstractmethod
    async def create_access_token(
        self,
        user_id: Union[str, UUID],
        roles: list[str] = None,
        expires_delta_minutes: Optional[int] = None,
    ) -> str:
        """
        Create a JWT access token for authentication.

        Args:
            user_id: The user ID to encode in the token
            roles: The user roles to encode in the token
            expires_delta_minutes: Custom expiration time in minutes

        Returns:
            JWT access token as a string
        """
        pass

    @abstractmethod
    async def create_refresh_token(
        self, user_id: Union[str, UUID], expires_delta_minutes: Optional[int] = None
    ) -> str:
        """
        Create a JWT refresh token that can be used to generate new access tokens.

        Args:
            user_id: The user ID to encode in the token
            expires_delta_minutes: Custom expiration time in minutes

        Returns:
            JWT refresh token as a string
        """
        pass

    @abstractmethod
    async def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify a JWT token's validity and return its decoded payload.

        Args:
            token: The JWT token to verify

        Returns:
            Decoded token payload as a dictionary

        Raises:
            JWTError: If token is invalid, expired, or has been tampered with
        """
        pass

    @abstractmethod
    async def refresh_access_token(self, refresh_token: str) -> str:
        """
        Generate a new access token using a valid refresh token.

        Args:
            refresh_token: The refresh token to use

        Returns:
            New JWT access token

        Raises:
            JWTError: If refresh token is invalid, expired, or not a refresh token
        """
        pass

    @abstractmethod
    async def blacklist_token(self, token: str, expires_at: datetime) -> None:
        """
        Add a token to the blacklist to prevent its future use.

        Args:
            token: The token to blacklist
            expires_at: When the token expires (for cleanup purposes)

        Raises:
            JWTError: If token blacklisting fails
        """
        pass

    @abstractmethod
    async def is_token_blacklisted(self, token: str) -> bool:
        """
        Check if a token has been blacklisted.

        Args:
            token: The token to check

        Returns:
            True if blacklisted, False otherwise
        """
        pass

    @abstractmethod
    async def get_token_identity(self, token: str) -> Union[str, UUID]:
        """
        Extract the user identity from a token.

        Args:
            token: The token to extract identity from

        Returns:
            User ID from the token

        Raises:
            JWTError: If token is invalid or doesn't contain identity
        """
        pass
