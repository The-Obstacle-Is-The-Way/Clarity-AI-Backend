"""
In-Memory Token Blacklist Repository.

This module provides an in-memory implementation of the token blacklist
repository interface for testing and development purposes.
"""

import hashlib
from datetime import datetime, timezone

from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.domain.exceptions.repository import RepositoryException
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)


class InMemoryTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    In-memory implementation of token blacklist repository for testing.

    This implementation stores blacklisted tokens in memory and is intended
    for use in testing and development environments only. It is not suitable
    for production use as it does not persist data across application restarts
    and cannot be shared across multiple instances.
    """

    def __init__(self):
        """Initialize the in-memory token blacklist repository."""
        # Structure: {token_hash: {"jti": jti, "expires_at": datetime}}
        self._token_blacklist: dict[str, dict] = {}

        # Structure: {jti: {"expires_at": datetime, "reason": str}}
        self._jti_blacklist: dict[str, dict] = {}

        # Structure: {session_id: Set[jti]}
        self._session_tokens: dict[str, set[str]] = {}

        logger.info("InMemoryTokenBlacklistRepository initialized")

    def _hash_token(self, token: str) -> str:
        """
        Create a secure hash of a token to avoid storing actual tokens.

        Args:
            token: The token to hash

        Returns:
            str: Secure hash of the token
        """
        return hashlib.sha256(token.encode()).hexdigest()

    async def add_to_blacklist(
        self, token_jti: str, expires_at: datetime
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            token_jti: JWT ID - unique identifier for the token
            expires_at: When the token expires

        Raises:
            RepositoryException: If blacklisting fails
        """
        try:
            # Check if token has already expired
            now = datetime.now(timezone.utc)
            if expires_at <= now:
                # Token already expired, no need to blacklist
                logger.debug(f"Token {token_jti} already expired, skipping blacklist")
                return

            # Store JTI reference
            self._jti_blacklist[token_jti] = {
                "expires_at": expires_at,
                "reason": "manual_blacklist",
            }

            logger.info(f"Token {token_jti} blacklisted until {expires_at.isoformat()}")
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e!s}")
            raise RepositoryException(f"Failed to blacklist token: {e!s}")

    async def is_blacklisted(self, token_jti: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token_jti: The token JTI to check

        Returns:
            True if blacklisted, False otherwise

        Raises:
            RepositoryException: If check fails
        """
        try:
            # If not in blacklist, return False
            if token_jti not in self._jti_blacklist:
                return False

            # Check if token has expired from the blacklist
            jti_info = self._jti_blacklist[token_jti]
            if jti_info["expires_at"] < datetime.now(timezone.utc):
                # Clean up expired token
                del self._jti_blacklist[token_jti]
                return False

            return True
        except Exception as e:
            logger.error(f"Failed to check token blacklist: {e!s}")
            # For security, assume token is blacklisted if check fails
            return True





    async def remove_expired(self) -> int:
        """
        Remove expired entries from the blacklist.

        Returns:
            Number of entries removed

        Raises:
            RepositoryException: If cleanup fails
        """
        try:
            now = datetime.now(timezone.utc)
            removed_count = 0

            # Clean up expired JTIs
            jtis_to_remove = []
            for jti, jti_info in self._jti_blacklist.items():
                if jti_info["expires_at"] < now:
                    jtis_to_remove.append(jti)

            for jti in jtis_to_remove:
                del self._jti_blacklist[jti]
                removed_count += 1

            logger.info(f"Removed {removed_count} expired entries from token blacklist")
            return removed_count
        except Exception as e:
            logger.error(f"Failed to remove expired entries: {e!s}")
            raise RepositoryException(f"Failed to remove expired entries: {e!s}")

    async def get_all_blacklisted(self) -> list[dict]:
        """
        Get all blacklisted tokens.

        Returns:
            List of dictionaries containing token_jti and expires_at

        Raises:
            RepositoryException: If retrieval fails
        """
        try:
            return [
                {"token_jti": jti, "expires_at": data["expires_at"]}
                for jti, data in self._jti_blacklist.items()
            ]
        except Exception as e:
            logger.error(f"Failed to get all blacklisted tokens: {e!s}")
            raise RepositoryException(f"Failed to get all blacklisted tokens: {e!s}")

    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """
        Remove a specific token from the blacklist.

        Args:
            token_jti: The unique JWT ID to remove

        Returns:
            True if token was removed, False if not found

        Raises:
            RepositoryException: If removal fails
        """
        try:
            if token_jti in self._jti_blacklist:
                del self._jti_blacklist[token_jti]
                logger.info(f"Removed token {token_jti} from blacklist")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove token from blacklist: {e!s}")
            raise RepositoryException(f"Failed to remove token from blacklist: {e!s}")
