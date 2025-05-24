"""
Redis implementation of the token blacklist repository.

This implementation provides a persistent, distributed token blacklist using Redis,
making it suitable for production use in a HIPAA-compliant environment.
"""

import json
from datetime import datetime

import redis.asyncio as redis
from redis.exceptions import RedisError

from app.core.config.settings import get_settings
from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.core.logger import get_logger

logger = get_logger(__name__)


class RedisTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    Redis implementation of the token blacklist repository.

    This implementation uses Redis to store blacklisted tokens, providing:
    - Persistence across application restarts
    - Automatic expiration of blacklisted tokens
    - Distribution across multiple application instances
    """

    def __init__(self, redis_client: redis.Redis | None = None, key_prefix: str = "blacklist:"):
        """
        Initialize the Redis token blacklist repository.

        Args:
            redis_client: Redis client instance. If not provided, one will be created.
            key_prefix: Prefix for Redis keys to avoid collisions
        """
        self._redis = redis_client
        self._key_prefix = key_prefix

        if self._redis is None:
            settings = get_settings()
            try:
                self._redis = redis.Redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                )
                logger.info("Redis token blacklist repository initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Redis client: {e}")
                raise

    async def add_to_blacklist(
        self, token_jti: str, expires_at: datetime
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            token_jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
        """
        try:
            # Calculate TTL in seconds
            expiry_timestamp = expires_at.timestamp()
            current_timestamp = datetime.now().timestamp()
            ttl = max(int(expiry_timestamp - current_timestamp), 1)  # Ensure at least 1 second TTL

            # Store token data
            token_data = {
                "jti": token_jti,
                "reason": "blacklisted",
                "blacklisted_at": datetime.now().isoformat(),
                "expires_at": expires_at.isoformat(),
            }

            # Store by JTI for faster lookups
            jti_key = f"{self._key_prefix}jti:{token_jti}"
            await self._redis.setex(jti_key, ttl, json.dumps(token_data))

            logger.debug(f"Token with JTI {token_jti} blacklisted until {expires_at}")
        except RedisError as e:
            logger.error(f"Redis error when adding token to blacklist: {e}")
            # Re-raise as application-specific exception if needed
            raise

    async def is_blacklisted(self, token_jti: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token_jti: The token JTI to check

        Returns:
            True if the token is blacklisted, False otherwise
        """
        try:
            jti_key = f"{self._key_prefix}jti:{token_jti}"
            return await self._redis.exists(jti_key) > 0
        except RedisError as e:
            logger.error(f"Redis error when checking token blacklist: {e}")
            # Assume not blacklisted on Redis failure (fail-open)
            # For stricter security, return True here (fail-closed)
            return False

    async def remove_expired(self) -> int:
        """
        Remove expired tokens from the blacklist.
        
        Redis automatically handles expiration, so this method
        primarily serves to count expired keys if needed.

        Returns:
            Number of tokens removed (always 0 for Redis auto-expiry)
        """
        # Redis handles automatic expiration via TTL
        # Return 0 since Redis auto-removes expired keys
        return 0

    async def get_all_blacklisted(self) -> list[dict]:
        """
        Get all blacklisted tokens.

        Returns:
            List of dictionaries containing token_jti and expires_at
        """
        try:
            pattern = f"{self._key_prefix}jti:*"
            keys = await self._redis.keys(pattern)
            
            result = []
            for key in keys:
                data = await self._redis.get(key)
                if data:
                    token_data = json.loads(data)
                    result.append({
                        "token_jti": token_data["jti"],
                        "expires_at": datetime.fromisoformat(token_data["expires_at"])
                    })
            
            return result
        except RedisError as e:
            logger.error(f"Redis error when getting all blacklisted tokens: {e}")
            return []

    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """
        Remove a specific token from the blacklist.

        Args:
            token_jti: The unique JWT ID to remove

        Returns:
            True if token was removed, False if not found
        """
        try:
            jti_key = f"{self._key_prefix}jti:{token_jti}"
            deleted = await self._redis.delete(jti_key)
            return deleted > 0
        except RedisError as e:
            logger.error(f"Redis error when removing token from blacklist: {e}")
            return False
