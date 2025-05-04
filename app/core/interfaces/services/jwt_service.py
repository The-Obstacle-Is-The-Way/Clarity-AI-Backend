"""
Interface definition for JWT Service.

Defines the contract for creating and validating JSON Web Tokens.
"""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any

# Attempt to import User, handle potential circular dependency or missing file gracefully
try:
    from app.domain.entities.user import User
except ImportError:
    User = Any # Fallback if User cannot be imported

# Import AuthenticationError - adjust path if necessary


class IJwtService(ABC):
    """Abstract base class for JWT operations."""

    @abstractmethod
    async def create_access_token(
        self, 
        data: dict[str, Any], 
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None
    ) -> str:
        """Creates a new access token."""
        pass

    @abstractmethod
    async def create_refresh_token(
        self, 
        data: dict[str, Any], 
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None
    ) -> str:
        """Creates a new refresh token."""
        pass

    @abstractmethod
    async def decode_token(self, token: str) -> dict[str, Any]:
        """
        Decodes a token and returns its payload.
        Raises AuthenticationError if the token is invalid or expired.
        """
        pass

    @abstractmethod
    async def get_user_from_token(self, token: str) -> User | None:
        """
        Decodes a token and retrieves the corresponding user.
        Returns None if the user is not found or the token is invalid.
        Raises AuthenticationError for token issues.
        """
        pass

    @abstractmethod
    async def verify_refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Verifies a refresh token and returns its payload.
        Raises AuthenticationError if invalid.
        """
        pass

    @abstractmethod
    def get_token_payload_subject(self, payload: dict[str, Any]) -> str | None:
        """Extracts the subject (user identifier) from the token payload."""
        pass 