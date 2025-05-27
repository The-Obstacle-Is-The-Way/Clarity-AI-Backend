"""
Redis-based Token Blacklist Repository.

This module provides a concrete implementation of the token blacklist repository
interface using Redis as the storage backend. This implementation is designed
for production use to properly manage token invalidation for HIPAA compliance.
"""

import hashlib
from datetime import datetime, timezone

from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.domain.exceptions.repository import RepositoryException
from app.infrastructure.logging.logger import get_logger

# Import RedisCacheService from the correct path
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

    def __init__(self, redis_service: RedisCacheService) -> None:
        """
        Initialize the Redis token blacklist repository.

        Args:
            redis_service: Redis service for storage operations
        """
        self._redis = redis_service
        # Redis key prefixes for different blacklist types
        self._token_prefix = "blacklist:token:"
        self._jti_prefix = "blacklist:jti:"
        self._session_prefix = "blacklist:session:"
        logger.info("RedisTokenBlacklistRepository initialized")

    async def add_to_blacklist(self, token_jti: str, expires_at: datetime) -> None:
        """
        Add a token to the blacklist by its JTI (JWT ID).

        Args:
            token_jti: The unique JWT ID of the token to blacklist
            expires_at: When the token would normally expire

        Raises:
            RepositoryException: If blacklisting fails
        """
        try:
            # Calculate remaining seconds until expiration
            now = datetime.now(timezone.utc)
            if expires_at <= now:
                # Token already expired, no need to blacklist
                logger.debug(f"Token {token_jti} already expired, skipping blacklist")
                return

            seconds_until_expiry = int((expires_at - now).total_seconds())
            # Add a small buffer (1 hour) to ensure token remains blacklisted
            # even in case of clock skew between servers
            expiry_buffer = 3600  # 1 hour in seconds
            ttl = seconds_until_expiry + expiry_buffer

            # Store JTI reference
            jti_key = f"{self._jti_prefix}{token_jti}"
            jti_data = {
                "expires_at": expires_at.isoformat(),
                "reason": "manual_blacklist",
            }
            await self._redis.set(jti_key, jti_data, ttl=ttl)

            # Add to active JTIs set for efficient retrieval
            await self._add_to_active_jtis(token_jti, ttl)

            logger.info(f"Token {token_jti} blacklisted until {expires_at.isoformat()}")
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e!s}")
            raise RepositoryException(f"Failed to blacklist token: {e!s}") from e

    async def is_blacklisted(self, token_jti: str) -> bool:
        """
        Check if a token is blacklisted by its JTI.

        Args:
            token_jti: The unique JWT ID to check

        Returns:
            True if blacklisted, False otherwise

        Raises:
            RepositoryException: If check fails
        """
        try:
            jti_key = f"{self._jti_prefix}{token_jti}"
            result = await self._redis.get(jti_key)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to check token blacklist: {e!s}")
            # For security, assume token is blacklisted if check fails
            return True

    def _hash_token(self, token: str) -> str:
        """
        Create a secure hash of a token for storage.

        Args:
            token: The token to hash

        Returns:
            str: Hashed token value for secure storage
        """
        # Use SHA-256 for token hashing - secure and suitable for tokens
        hash_obj = hashlib.sha256(token.encode())
        return hash_obj.hexdigest()

    async def get_all_blacklisted(self) -> list[dict]:
        """
        Get all blacklisted tokens.

        Note: This implementation maintains a set of active JTI keys for efficient retrieval
        since Redis pattern scanning is not available in the cache service.

        Returns:
            List[dict]: List of dictionaries containing token_jti and expires_at
        """
        try:
            # Get the set of active JTI keys
            active_jtis_key = f"{self._jti_prefix}active_set"
            active_jtis_data = await self._redis.get(active_jtis_key)

            if not active_jtis_data:
                return []

            # Parse the active JTIs list
            if isinstance(active_jtis_data, str):
                try:
                    active_jtis = active_jtis_data.split(",") if active_jtis_data else []
                except (ValueError, TypeError):
                    active_jtis = []
            else:
                active_jtis = active_jtis_data if isinstance(active_jtis_data, list) else []

            result = []
            for jti in active_jtis:
                if not jti:
                    continue

                # Get the data for this JTI
                jti_key = f"{self._jti_prefix}{jti}"
                jti_data = await self._redis.get(jti_key)

                if jti_data and isinstance(jti_data, dict):
                    try:
                        expires_at_str = jti_data.get("expires_at")
                        if expires_at_str:
                            expires_at = datetime.fromisoformat(expires_at_str)
                            result.append({"token_jti": jti, "expires_at": expires_at})
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid expiration format for JTI {jti}")

            return result
        except Exception as e:
            logger.error(f"Error retrieving blacklisted tokens: {e!s}")
            raise RepositoryException(f"Failed to retrieve blacklisted tokens: {e!s}") from e

    async def remove_expired(self) -> int:
        """
        Remove expired tokens from the blacklist to maintain performance.

        Returns:
            int: Number of expired tokens removed from blacklist
        """
        # Redis handles TTL expiration automatically through its built-in TTL mechanism,
        # so this is a no-op implementation for interface compliance.
        logger.debug("Expired token cleanup not needed with Redis TTL - handled automatically")
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
            exists = await self._redis.exists(jti_key)

            if not exists:
                return False

            # Remove the JTI entry
            await self._redis.delete(jti_key)

            # Remove from active JTIs set
            await self._remove_from_active_jtis(token_jti)

            logger.info(f"Removed token with JTI {token_jti} from blacklist")
            return True
        except Exception as e:
            logger.error(f"Error removing token from blacklist: {e!s}")
            raise RepositoryException(f"Failed to remove token from blacklist: {e!s}") from e

    async def _add_to_active_jtis(self, jti: str, ttl: int) -> None:
        """Add a JTI to the active set for efficient retrieval."""
        try:
            active_jtis_key = f"{self._jti_prefix}active_set"
            current_data = await self._redis.get(active_jtis_key)

            if current_data:
                if isinstance(current_data, str):
                    active_jtis = current_data.split(",") if current_data else []
                else:
                    active_jtis = current_data if isinstance(current_data, list) else []
            else:
                active_jtis = []

            if jti not in active_jtis:
                active_jtis.append(jti)
                # Store as comma-separated string for simplicity
                await self._redis.set(active_jtis_key, ",".join(active_jtis), ttl=ttl + 3600)

        except Exception as e:
            logger.warning(f"Failed to add JTI to active set: {e!s}")

    async def _remove_from_active_jtis(self, jti: str) -> None:
        """Remove a JTI from the active set."""
        try:
            active_jtis_key = f"{self._jti_prefix}active_set"
            current_data = await self._redis.get(active_jtis_key)

            if current_data:
                if isinstance(current_data, str):
                    active_jtis = current_data.split(",") if current_data else []
                else:
                    active_jtis = current_data if isinstance(current_data, list) else []

                if jti in active_jtis:
                    active_jtis.remove(jti)
                    # Update the set
                    if active_jtis:
                        await self._redis.set(active_jtis_key, ",".join(active_jtis))
                    else:
                        await self._redis.delete(active_jtis_key)

        except Exception as e:
            logger.warning(f"Failed to remove JTI from active set: {e!s}")
