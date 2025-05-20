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
        self, token: str, jti: str, expires_at: datetime, reason: str | None = None
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            token: The token to blacklist
            jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
            reason: Reason for blacklisting (optional)
        """
        self._token_blacklist[token] = jti
        self._jti_blacklist[jti] = {"expires_at": expires_at, "reason": reason or "test_blacklist"}

    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token: The token to check

        Returns:
            True if the token is blacklisted, False otherwise
        """
        return token in self._token_blacklist

    async def is_jti_blacklisted(self, token_id: str) -> bool:
        """
        Check if a token ID (JTI) is blacklisted.

        Args:
            token_id: The token ID (JTI) to check

        Returns:
            True if the token ID is blacklisted, False otherwise
        """
        return token_id in self._jti_blacklist

    async def clear_expired_tokens(self) -> int:
        """
        Remove expired tokens from the blacklist.

        Returns:
            The number of tokens removed from the blacklist
        """
        # In the mock implementation, we'll just return 0
        # as this is mainly for testing
        return 0
