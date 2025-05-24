"""
Interface for token blacklist repository to maintain a clean architecture boundary and
ensure proper token invalidation capabilities for enhanced security.

This interface defines the contract that token blacklist implementations must follow,
enabling proper JWT invalidation while maintaining Clean Architecture principles.
"""

from abc import ABC, abstractmethod
from datetime import datetime


class ITokenBlacklistRepository(ABC):
    """Interface for JWT token blacklisting repository.

    This interface ensures all token blacklist implementations provide consistent
    methods for tracking invalidated tokens, supporting features like token revocation,
    logout, and security breach responses.
    """

    @abstractmethod
    async def add_to_blacklist(self, token_jti: str, expires_at: datetime) -> None:
        """Add a token to the blacklist by its JTI (JWT ID).

        Args:
            token_jti: The unique JWT ID of the token to blacklist
            expires_at: When the token would normally expire
        """
        pass

    @abstractmethod
    async def is_blacklisted(self, token_jti: str) -> bool:
        """Check if a token is blacklisted by its JTI.

        Args:
            token_jti: The unique JWT ID to check

        Returns:
            bool: True if token is blacklisted, False otherwise
        """
        pass

    @abstractmethod
    async def remove_expired(self) -> int:
        """Remove expired tokens from the blacklist to maintain performance.

        Returns:
            int: Number of expired tokens removed from blacklist
        """
        pass

    @abstractmethod
    async def get_all_blacklisted(self) -> list[dict]:
        """Get all blacklisted tokens.

        Returns:
            List[dict]: List of dictionaries containing token_jti and expires_at
        """
        pass

    @abstractmethod
    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """Remove a specific token from the blacklist.

        Args:
            token_jti: The unique JWT ID to remove

        Returns:
            bool: True if token was removed, False if not found
        """
        pass
