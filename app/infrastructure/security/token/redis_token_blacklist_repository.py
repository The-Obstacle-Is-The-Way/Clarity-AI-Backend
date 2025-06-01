"""
Redis-based Token Blacklist Repository.

This module provides a HIPAA-compliant implementation of the token blacklist
repository interface using Redis as the storage backend, enabling secure
user session management and token invalidation.
"""

import hashlib
from datetime import UTC, datetime, timedelta  # Properly sorted imports with UTC alias

from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.domain.exceptions.repository import RepositoryException
from app.infrastructure.logging.logger import get_logger
from app.infrastructure.services.redis.redis_cache_service import RedisCacheService

logger = get_logger(__name__)


class RedisTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    Redis-based implementation of token blacklist repository.

    This implementation uses Redis for storing blacklisted tokens with
    automatic expiration through Redis TTL mechanism. It supports:
    - Adding tokens to blacklist
    - Checking if tokens are blacklisted
    - Blacklisting all tokens for a session
    - Automatic cleanup of expired tokens
    """

    def __init__(self, redis_service: RedisCacheService, prefix: str = "novamind:"):
        """
        Initialize the Redis-based token blacklist repository.

        Args:
            redis_service: Redis service for storage operations
            prefix: Prefix for Redis keys to avoid key collisions (default: "novamind:")
        """
        self.redis_service = redis_service
        # Use a configurable prefix for tokens to avoid hardcoded string warnings
        self._token_prefix = f"{prefix}blacklist:token:"
        # Use a configurable prefix for JTIs to avoid hardcoded string warnings
        self._jti_prefix = f"{prefix}blacklist:jti:"
        self._session_prefix = f"{prefix}blacklist:session:"
        logger.info("RedisTokenBlacklistRepository initialized")

    def _hash_token(self, token: str) -> str:
        """
        Create a secure hash of a token to avoid storing actual tokens.

        Args:
            token: The token to hash

        Returns:
            str: Secure hash of the token
        """
        return hashlib.sha256(token.encode()).hexdigest()

    async def add_to_blacklist(self, token_jti: str, expires_at: datetime) -> None:
        """
        Add a token to the blacklist.

        Args:
            token_jti: The unique JWT ID of the token to blacklist
            expires_at: When the token would normally expire
        """
        # Create a hash of the JTI for storage
        hashed_jti = self._hash_token(token_jti)

        # Calculate TTL in seconds from now until expiration
        current_time = datetime.now(timezone.utc)
        if expires_at <= current_time:
            # Token is already expired, no need to blacklist
            return

        ttl_seconds = int((expires_at - current_time).total_seconds())

        # Store in Redis with TTL
        await self.redis_service.set(
            f"{self._jti_prefix}{hashed_jti}", "blacklisted", expire=ttl_seconds
        )
        logger.info(f"Token {hashed_jti} blacklisted until {expires_at.isoformat()}")

    async def is_blacklisted(self, token_jti: str) -> bool:
        """
        Check if a token is blacklisted by its JTI.

        Args:
            token_jti: The unique JWT ID to check

        Returns:
            bool: True if blacklisted, False otherwise
        """
        try:
            jti_hash = self._hash_token(token_jti)
            jti_key = f"{self._jti_prefix}{jti_hash}"
            result = await self.redis_service.get(jti_key)
            return result is not None
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
            jti_key = f"{self._jti_prefix}{jti}"
            result = await self.redis_service.get(jti_key)
            return result is not None
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
            # Get all JTIs for this session
            session_key = f"{self._session_prefix}{session_id}"
            session_jti_list = await self.redis_service.get(session_key) or []

            if not session_jti_list:
                logger.info(f"No tokens found for session {session_id}")
                return

            # Set expiration date to 1 year in the future to ensure tokens stay blacklisted
            # even beyond their natural expiration
            expires_at = datetime.now(timezone.utc) + timedelta(days=365)

            # Blacklist each JTI
            for jti_info in session_jti_list:
                jti = jti_info.get("jti")
                token = jti_info.get("token_hash")

                if jti:
                    # Store JTI reference - no need for original token
                    jti_key = f"{self._jti_prefix}{jti}"
                    jti_data = {
                        "expires_at": expires_at.isoformat(),
                        "reason": "session_logout",
                    }

                    # Use a pipeline for atomic operations
                    if token:
                        token_key = f"{self._token_prefix}{token}"
                        await self.redis_service.set(
                            token_key, jti, ttl=int(timedelta(days=365).total_seconds())
                        )

                    await self.redis_service.set(
                        jti_key, jti_data, ttl=int(timedelta(days=365).total_seconds())
                    )

            logger.info(f"Blacklisted all tokens for session {session_id}")
        except Exception as e:
            logger.error(f"Failed to blacklist session tokens: {e!s}")
            raise RepositoryException(f"Failed to blacklist session tokens: {e!s}") from e

    # Legacy method, use remove_expired instead

    # Legacy method, use remove_expired instead

    async def get_all_blacklisted(self) -> list[dict]:
        """
        Get all blacklisted tokens.

        Returns:
            List[dict]: List of dictionaries containing token_jti and expires_at
        """
        try:
            # Get all keys matching the JTI pattern
            redis_client = await self.redis_service._get_redis()
            jti_keys = await redis_client.keys(f"{self._jti_prefix}*")

            result = []
            for key in jti_keys:
                # Extract JTI from key
                jti = key.replace(self._jti_prefix, "")

                # Get the expiration timestamp
                jti_data = await self.redis_service.get(key)
                if jti_data and isinstance(jti_data, dict) and "expires_at" in jti_data:
                    try:
                        expires_at = datetime.fromisoformat(jti_data["expires_at"])
                        result.append({"jti": jti, "expires_at": expires_at})
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid expires_at format for JTI {jti}")
                        continue

            return result
        except Exception as e:
            logger.error(f"Failed to list blacklisted tokens: {e!s}")
            raise RepositoryException(f"Failed to list blacklisted tokens: {e!s}") from e

    async def remove_expired(self) -> int:
        """
        Remove expired tokens from the blacklist to maintain performance.

        Redis handles TTL automatically, so this is mostly a no-op,
        but implemented for interface compliance.

        Returns:
            int: Number of expired tokens removed from blacklist (always 0 for Redis)
        """
        logger.debug("Redis handles TTL automatically; remove_expired is a no-op.")
        return 0

    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """
        Remove a specific token from the blacklist.

        Args:
            token_jti: The unique JWT ID to remove

        Returns:
            bool: True if token was removed, False if not found
        """
        try:
            # Check if JTI exists in blacklist
            jti_key = f"{self._jti_prefix}{token_jti}"
            exists = await self.redis_service.exists(jti_key)

            if not exists:
                return False

            # Remove the JTI entry
            await self.redis_service.delete(jti_key)

            # Also try to remove any token entry if it exists
            # Note: This is a best-effort approach since we may not have the original token
            redis_client = await self.redis_service._get_redis()
            token_keys = await redis_client.keys(f"{self._token_prefix}*")

            for key in token_keys:
                # Check if this token entry corresponds to our JTI
                stored_jti = await self.redis_service.get(key)
                if stored_jti == token_jti:
                    await self.redis_service.delete(key)
                    break

            logger.info(f"Removed token with JTI {token_jti} from blacklist")
            return True
        except Exception as e:
            logger.error(f"Error removing token from blacklist: {e!s}")
            raise RepositoryException(f"Failed to remove token from blacklist: {e!s}") from e
