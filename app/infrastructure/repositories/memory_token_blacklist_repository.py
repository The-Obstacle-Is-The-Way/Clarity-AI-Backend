"""
In-memory implementation of the token blacklist repository.

This is primarily for testing and development environments. 
For production, use RedisTokenBlacklistRepository or another persistent implementation.
"""

from datetime import datetime, timedelta

from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)


class MemoryTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    In-memory implementation of the token blacklist repository.

    This implementation stores blacklisted tokens in memory. It is not suitable for
    production use because tokens will be lost when the server restarts, and it
    doesn't scale across multiple instances.
    """

    def __init__(self):
        """Initialize the in-memory blacklist."""
        self._blacklist: dict[str, dict] = {}  # JTI -> token info
        self._token_to_jti: dict[str, str] = {}  # token -> JTI mapping

    async def add_to_blacklist(
        self, token: str, jti: str, expires_at: datetime, reason: str | None = None
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            token: The token value to blacklist
            jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
            reason: Reason for blacklisting (optional)
        """
        self._blacklist[jti] = {
            "expires_at": expires_at,
            "reason": reason,
            "blacklisted_at": datetime.now(),
        }
        self._token_to_jti[token] = jti

    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token: The token value to check

        Returns:
            True if the token is blacklisted, False otherwise
        """
        jti = self._token_to_jti.get(token)
        if not jti:
            return False
        return await self.is_jti_blacklisted(jti)

    async def is_jti_blacklisted(self, token_id: str) -> bool:
        """
        Check if a token ID (JTI) is blacklisted.

        Args:
            token_id: The token ID (JTI) to check

        Returns:
            True if the token ID is blacklisted, False otherwise
        """
        return token_id in self._blacklist

    async def cleanup_expired(self) -> int:
        """
        Remove expired tokens from the blacklist.

        Returns:
            Number of expired tokens removed
        """
        now = datetime.now()
        expired_jtis = [jti for jti, data in self._blacklist.items() if data["expires_at"] < now]

        # Clean up token to JTI mapping
        for token, jti in list(self._token_to_jti.items()):
            if jti in expired_jtis:
                del self._token_to_jti[token]

        # Clean up blacklist
        for jti in expired_jtis:
            del self._blacklist[jti]

        return len(expired_jtis)

    async def clear_expired_tokens(self) -> int:
        """
        Remove expired tokens from the blacklist.
        This is an alias for cleanup_expired to satisfy the interface.

        Returns:
            Number of expired tokens removed
        """
        return await self.cleanup_expired()

    async def blacklist_session(self, session_id: str) -> bool:
        """
        Blacklist all tokens associated with a session.

        Args:
            session_id: The session ID to blacklist
        """
        # In memory implementation just stores the session ID
        # A real implementation would blacklist all tokens related to this session
        try:
            self._blacklist[f"session:{session_id}"] = {
                "expires_at": datetime.now() + timedelta(days=30),  # Long expiry for sessions
                "reason": "Session blacklisted",
                "blacklisted_at": datetime.now(),
            }
            return True
        except Exception:
            return False
