"""Interface for JWT (JSON Web Token) services.

This interface defines the contract for services that handle JWT token generation,
validation, and management according to HIPAA security standards.
"""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any

from app.domain.entities.user import User


class IJwtService(ABC):
    """Interface for services that handle JWT token operations."""

    @abstractmethod
    def create_access_token(
        self,
        subject: str | None = None,
        additional_claims: dict[str, Any] | None = None,
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None,
        data: dict[str, Any] | Any | None = None,
    ) -> str:
        """Creates a new access token.

        Args:
            subject: The subject of the token (typically a user ID)
            additional_claims: Additional claims to include in the token
            expires_delta: Custom expiration time as timedelta
            expires_delta_minutes: Custom expiration time in minutes
            data: Alternative way to provide token data (for compatibility with tests)
                  When provided, this can contain both subject and claims in one object

        Returns:
            The encoded JWT token as a string
        """
        pass

    @abstractmethod
    def create_refresh_token(
        self,
        subject: str | None = None,
        additional_claims: dict[str, Any] | None = None,
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None,
        data: dict[str, Any] | Any | None = None,
    ) -> str:
        """Creates a new refresh token.

        Args:
            subject: The subject of the token (typically a user ID)
            additional_claims: Additional claims to include in the token
            expires_delta: Custom expiration time as timedelta
            expires_delta_minutes: Custom expiration time in minutes
            data: Alternative way to provide token data (for compatibility with tests)
                  When provided, this can contain both subject and claims in one object

        Returns:
            The encoded JWT refresh token as a string
        """
        pass

    @abstractmethod
    def decode_token(
        self,
        token: str,
        verify_signature: bool = True,
        options: dict[str, Any] | None = None,
        audience: str | None = None,
        algorithms: list[str] | None = None,
    ) -> Any:
        """Decode and validate a JWT token.

        Args:
            token: JWT token to decode
            verify_signature: Whether to verify token signature
            options: Options for decoding
            audience: Expected audience
            algorithms: List of allowed algorithms

        Returns:
            Decoded token payload
        """
        pass

    @abstractmethod
    async def get_user_from_token(self, token: str) -> User | None:
        """Get the user associated with a token."""
        pass

    @abstractmethod
    def verify_refresh_token(self, refresh_token: str) -> Any:
        """Verify that a token is a valid refresh token."""
        pass

    @abstractmethod
    def get_token_payload_subject(self, payload: Any) -> str | None:
        """Extracts the subject (user identifier) from the token payload.

        Args:
            payload: Token payload

        Returns:
            Subject string (user ID) if present, None otherwise
        """
        pass

    @abstractmethod
    def refresh_access_token(self, refresh_token: str) -> str:
        """Refresh an access token using a valid refresh token."""
        pass

    @abstractmethod
    async def revoke_token(self, token: str) -> bool:
        """Revokes a token by adding its JTI to the blacklist.

        Args:
            token: Token to revoke

        Returns:
            True if token was successfully revoked, False otherwise
        """
        pass

    @abstractmethod
    async def logout(self, token: str) -> bool:
        """Log out a user by revoking their token.

        Args:
            token: JWT token to revoke

        Returns:
            True if logout was successful, False otherwise
        """
        pass

    @abstractmethod
    async def blacklist_session(self, session_id: str) -> bool:
        """Blacklist all tokens associated with a session.

        Args:
            session_id: ID of the session to blacklist

        Returns:
            True if session was blacklisted, False otherwise
        """
        pass
