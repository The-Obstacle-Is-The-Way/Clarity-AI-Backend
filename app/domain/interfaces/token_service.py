"""
Token Service Interface.

This module defines the interface for token management services.
"""

from abc import ABC, abstractmethod
from typing import Any

from app.domain.entities.user import User

class TokenService(ABC):
    """Interface for token management services."""

    @abstractmethod
    async def create_access_token(self, data: dict, expires_delta: timedelta | None = None) -> str:
        """Creates a new access token."""
        pass

    @abstractmethod
    async def create_refresh_token(self, data: dict, expires_delta: timedelta | None = None) -> str:
        """Creates a new refresh token."""
        pass

    @abstractmethod
    async def verify_token(self, token: str, secret_key: str, algorithms: list[str]) -> dict[str, Any] | None:
        """Verifies a token and returns its payload."""
        pass

    @abstractmethod
    async def decode_token(self, token: str) -> dict[str, Any] | None:
        """Decodes a token payload without verification."""
        pass

    @abstractmethod
    async def get_token_payload(self, token: str) -> dict | None:
        """Retrieves the payload from a valid token."""
        pass

    @abstractmethod
    async def validate_token_for_user(self, token: str, user: User) -> bool:
        """Validates if the token belongs to the specified user."""
        pass

    @abstractmethod
    async def revoke_token(self, token: str) -> bool:
        """Revokes a specific token."""
        pass

    @abstractmethod
    async def is_token_revoked(self, token: str) -> bool:
        """Checks if a token has been revoked."""
        pass

    @abstractmethod
    async def get_user_from_token(self, token: str) -> User | None:
        """Retrieves the associated user from a token."""
        pass