"""Interface for JWT (JSON Web Token) services.

This interface defines the contract for services that handle JWT token generation,
validation, and management according to HIPAA security standards.
"""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any, Optional

try:
    from app.core.domain.entities.user import User
except ImportError:
    try:
        from app.domain.entities.user import User
    except ImportError:
        User = Any  # Fallback if User cannot be imported


class IJwtService(ABC):
    """Interface for services that handle JWT token operations."""

    @abstractmethod
    def create_access_token(
        self,
        subject: str,
        additional_claims: Dict[str, Any] | None = None,
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None,
    ) -> str:
        """Creates a new access token."""
        pass

    @abstractmethod
    def create_refresh_token(
        self,
        subject: str,
        additional_claims: Dict[str, Any] | None = None,
        additional_claims: dict[str, Any] | None = None,
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None,
    ) -> str:
        """Creates a new refresh token."""
        pass

    @abstractmethod
    def decode_token(self, token: str, verify_signature: bool = True) -> Any:
        """
        Decodes a token and returns its payload.
        
        Args:
            token: JWT token to decode
            verify_signature: Whether to verify the token signature
            
        Returns:
            Token payload
            
        Raises:
            AuthenticationError: If the token is invalid or expired
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
    def get_token_payload_subject(self, payload: Any) -> Optional[str]:
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
            token: JWT token to revoke
            
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
