"""
Mock Token Blacklist Repository for testing.

This module provides a simple in-memory implementation of the token blacklist
repository interface for use in unit tests.
"""

from datetime import datetime
from typing import Any

from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)


class MockTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    Mock implementation of token blacklist repository for testing.

    Stores blacklisted tokens in memory rather than requiring
    a Redis connection during tests.
    """

    def __init__(self):
        """Initialize with empty in-memory storage."""
        self._token_blacklist: dict[str, Any] = {}  # token -> jti
        self._jti_blacklist: dict[str, Any] = {}  # jti -> expiry_info

    async def add_to_blacklist(
        self, token_jti: str, expires_at: datetime
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            token_jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
        """
        self._jti_blacklist[token_jti] = {"expires_at": expires_at, "reason": "test_blacklist"}

    async def is_blacklisted(self, token_jti: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token_jti: The token JTI to check

        Returns:
            True if the token is blacklisted, False otherwise
        """
        return token_jti in self._jti_blacklist



    async def remove_expired(self) -> int:
        """
        Remove expired tokens from the blacklist.

        Returns:
            The number of tokens removed from the blacklist
        """
        # In the mock implementation, we'll just return 0
        # as this is mainly for testing
        return 0

    async def get_all_blacklisted(self) -> list[dict]:
        """
        Get all blacklisted tokens.

        Returns:
            List of dictionaries containing token_jti and expires_at
        """
        return [
            {"token_jti": jti, "expires_at": data["expires_at"]}
            for jti, data in self._jti_blacklist.items()
        ]

    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """
        Remove a specific token from the blacklist.

        Args:
            token_jti: The unique JWT ID to remove

        Returns:
            True if token was removed, False if not found
        """
        if token_jti in self._jti_blacklist:
            del self._jti_blacklist[token_jti]
            return True
        return False
