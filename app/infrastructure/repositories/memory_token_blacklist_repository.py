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
        self, token_jti: str, expires_at: datetime
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            token_jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
        """
        self._blacklist[token_jti] = {
            "expires_at": expires_at,
            "reason": "blacklisted",
            "blacklisted_at": datetime.now(),
        }

    async def is_blacklisted(self, token_jti: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token_jti: The token JTI to check

        Returns:
            True if the token is blacklisted, False otherwise
        """
        return token_jti in self._blacklist





    async def remove_expired(self) -> int:
        """
        Remove expired tokens from the blacklist.

        Returns:
            Number of expired tokens removed
        """
        now = datetime.now()
        expired_jtis = [jti for jti, data in self._blacklist.items() if data["expires_at"] < now]

        # Clean up blacklist
        for jti in expired_jtis:
            del self._blacklist[jti]

        return len(expired_jtis)

    async def get_all_blacklisted(self) -> list[dict]:
        """
        Get all blacklisted tokens.

        Returns:
            List of dictionaries containing token_jti and expires_at
        """
        return [
            {"token_jti": jti, "expires_at": data["expires_at"]}
            for jti, data in self._blacklist.items()
        ]

    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """
        Remove a specific token from the blacklist.

        Args:
            token_jti: The unique JWT ID to remove

        Returns:
            True if token was removed, False if not found
        """
        if token_jti in self._blacklist:
            del self._blacklist[token_jti]
            return True
        return False
