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

# Import TokenPayload from its new canonical location
try:
    # Ensure this path matches the actual location of TokenPayload in jwt_service.py
    from app.infrastructure.security.jwt_service import TokenPayload 
except ImportError:
    TokenPayload = Any # Fallback

# Import AuthenticationError - adjust path if necessary


class IJwtService(ABC):
    """Abstract base class for JWT operations."""

    @abstractmethod
    def create_access_token( # No longer async
        self, 
        data: dict[str, Any], 
        expires_delta: timedelta | None = None, 
        expires_delta_minutes: int | None = None 
    ) -> str:
        """Creates a new access token."""
        pass

    @abstractmethod
    def create_refresh_token( # No longer async
        self, 
        data: dict[str, Any], 
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None 
    ) -> str:
        """Creates a new refresh token."""
        pass

    @abstractmethod
    def decode_token(self, token: str) -> TokenPayload: # No longer async, returns TokenPayload
        """
        Decodes a token and returns its payload as a TokenPayload object.
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
    def verify_refresh_token(self, refresh_token: str) -> TokenPayload: # No longer async, returns TokenPayload
        """
        Verifies a refresh_token and returns its payload as a TokenPayload object.
        Raises AuthenticationError if invalid.
        """
        pass

    @abstractmethod
    def get_token_payload_subject(self, payload: TokenPayload) -> str | None: # Takes TokenPayload
        """Extracts the subject (user identifier) from the token payload."""
        pass

    @abstractmethod
    async def revoke_token(self, token: str) -> None: # Kept async to match JWTService
        """Revokes a token by adding its JTI to the blacklist."""
        pass 