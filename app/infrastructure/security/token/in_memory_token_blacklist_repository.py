"""
In-Memory Token Blacklist Repository.

This module provides an in-memory implementation of the token blacklist
repository interface for testing and development purposes.
"""

import hashlib
from datetime import UTC, datetime

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
        self, token: str, jti: str, expires_at: datetime, reason: str | None = None
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            token: The token to blacklist
            jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
            reason: Reason for blacklisting

        Raises:
            RepositoryException: If blacklisting fails
        """
        try:
            # Check if token has already expired
            now = datetime.now(UTC)
            if expires_at <= now:
                # Token already expired, no need to blacklist
                logger.debug(f"Token {jti} already expired, skipping blacklist")
                return

            # Store token hash
            token_hash = self._hash_token(token)
            self._token_blacklist[token_hash] = {"jti": jti, "expires_at": expires_at}

            # Store JTI reference
            self._jti_blacklist[jti] = {
                "expires_at": expires_at,
                "reason": reason or "manual_blacklist",
            }

            logger.info(
                f"Token {jti} blacklisted until {expires_at.isoformat()}, reason: {reason}"
            )
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e!s}")
            raise RepositoryException(f"Failed to blacklist token: {e!s}")

    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token: The token to check

        Returns:
            True if blacklisted, False otherwise

        Raises:
            RepositoryException: If check fails
        """
        try:
            token_hash = self._hash_token(token)

            # If not in blacklist, return False
            if token_hash not in self._token_blacklist:
                return False

            # Check if token has expired from the blacklist
            token_info = self._token_blacklist[token_hash]
            if token_info["expires_at"] < datetime.now(UTC):
                # Clean up expired token
                del self._token_blacklist[token_hash]
                return False

            return True
        except Exception as e:
            logger.error(f"Failed to check token blacklist: {e!s}")
            # For security, assume token is blacklisted if check fails
            return True

    async def is_jti_blacklisted(self, jti: str) -> bool:
        """
        Check if a token with specific JWT ID is blacklisted.

        Args:
            jti: JWT ID to check

        Returns:
            True if blacklisted, False otherwise

        Raises:
            RepositoryException: If check fails
        """
        try:
            # If not in blacklist, return False
            if jti not in self._jti_blacklist:
                return False

            # Check if JTI has expired from the blacklist
            jti_info = self._jti_blacklist[jti]
            if jti_info["expires_at"] < datetime.now(UTC):
                # Clean up expired JTI
                del self._jti_blacklist[jti]
                return False

            return True
        except Exception as e:
            logger.error(f"Failed to check JTI blacklist: {e!s}")
            # For security, assume JTI is blacklisted if check fails
            return True

    async def blacklist_session(self, session_id: str) -> None:
        """
        Blacklist all tokens for a specific session.

        Args:
            session_id: The session ID to blacklist

        Raises:
            RepositoryException: If blacklisting fails
        """
        try:
            # If no tokens for this session, return
            if session_id not in self._session_tokens:
                logger.info(f"No tokens found for session {session_id}")
                return

            # Get all JTIs for this session
            session_jtis = self._session_tokens[session_id]

            # Set a far-future expiration date
            expires_at = datetime.max

            # Blacklist each JTI
            for jti in session_jtis:
                self._jti_blacklist[jti] = {
                    "expires_at": expires_at,
                    "reason": "session_logout",
                }

            logger.info(f"Blacklisted all tokens for session {session_id}")
        except Exception as e:
            logger.error(f"Failed to blacklist session tokens: {e!s}")
            raise RepositoryException(f"Failed to blacklist session tokens: {e!s}")

    async def remove_expired_entries(self) -> int:
        """
        Remove expired entries from the blacklist.

        Returns:
            Number of entries removed

        Raises:
            RepositoryException: If cleanup fails
        """
        try:
            now = datetime.now(UTC)
            removed_count = 0

            # Clean up expired tokens
            token_hashes_to_remove = []
            for token_hash, token_info in self._token_blacklist.items():
                if token_info["expires_at"] < now:
                    token_hashes_to_remove.append(token_hash)

            for token_hash in token_hashes_to_remove:
                del self._token_blacklist[token_hash]
                removed_count += 1

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
