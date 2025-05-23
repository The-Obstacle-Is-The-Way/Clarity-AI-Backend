"""Interface for JWT (JSON Web Token) services.

This interface defines the contract for services that handle JWT token generation,
validation, and management according to HIPAA security standards.

Fixed Interface Segregation Principle and Liskov Substitution Principle violations:
- Added missing properties that consumers expect (secret_key, algorithm, etc.)
- Changed return types from Any to structured JWTPayload objects
- Ensured interface contract matches actual consumer requirements from tests
"""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any

from app.core.domain.types.jwt_payload import JWTPayload, RefreshTokenPayload
from app.domain.entities.user import User


class IJwtService(ABC):
    """Interface for services that handle JWT token operations.

    This interface defines the complete contract expected by consumers,
    including configuration properties and structured return types.
    """

    # Configuration Properties (Interface Segregation Principle compliance)
    # These properties are expected by consumers as revealed by test analysis

    @property
    @abstractmethod
    def secret_key(self) -> str:
        """JWT signing secret key."""
        pass

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """JWT signing algorithm (e.g., 'HS256')."""
        pass

    @property
    @abstractmethod
    def access_token_expire_minutes(self) -> int:
        """Access token expiration time in minutes."""
        pass

    @property
    @abstractmethod
    def refresh_token_expire_minutes(self) -> int:
        """Refresh token expiration time in minutes."""
        pass

    @property
    @abstractmethod
    def refresh_token_expire_days(self) -> int:
        """Refresh token expiration time in days (computed from minutes)."""
        pass

    @property
    @abstractmethod
    def token_issuer(self) -> str | None:
        """JWT token issuer."""
        pass

    @property
    @abstractmethod
    def token_audience(self) -> str | None:
        """JWT token audience."""
        pass

    # Token Creation Methods

    @abstractmethod
    def create_access_token(
        self,
        subject: str | None = None,
        additional_claims: dict[str, Any] | None = None,
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None,
        data: dict[str, Any] | None = None,
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
        data: dict[str, Any] | None = None,
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

    # Token Validation Methods (Liskov Substitution Principle compliance)
    # Fixed return types from Any to structured JWTPayload objects

    @abstractmethod
    def decode_token(
        self,
        token: str,
        verify_signature: bool = True,
        options: dict[str, Any] | None = None,
        audience: str | None = None,
        algorithms: list[str] | None = None,
    ) -> JWTPayload:
        """Decode and validate a JWT token.

        Args:
            token: JWT token to decode
            verify_signature: Whether to verify token signature
            options: Options for decoding (e.g., {'verify_exp': False})
            audience: Expected audience
            algorithms: List of allowed algorithms

        Returns:
            Structured JWT payload object with proper attribute access

        Raises:
            InvalidTokenException: If token is invalid
            TokenExpiredException: If token is expired
        """
        pass

    @abstractmethod
    def verify_refresh_token(self, refresh_token: str) -> RefreshTokenPayload:
        """Verify that a token is a valid refresh token.

        Args:
            refresh_token: Token to verify as refresh token

        Returns:
            Structured refresh token payload

        Raises:
            InvalidTokenException: If token is not a valid refresh token
        """
        pass

    @abstractmethod
    def get_token_payload_subject(self, payload: JWTPayload) -> str | None:
        """Extracts the subject (user identifier) from the token payload.

        Args:
            payload: Structured token payload

        Returns:
            Subject string (user ID) if present, None otherwise
        """
        pass

    # User and Session Management

    @abstractmethod
    async def get_user_from_token(self, token: str) -> User | None:
        """Get the user associated with a token.

        Args:
            token: JWT token to extract user from

        Returns:
            User entity if found, None otherwise
        """
        pass

    @abstractmethod
    def refresh_access_token(self, refresh_token: str) -> str:
        """Refresh an access token using a valid refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New access token string

        Raises:
            InvalidTokenException: If refresh token is invalid
        """
        pass

    # Token Revocation and Session Management

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


# Type alias for the interface (for backward compatibility)
JWTServiceInterface = IJwtService
