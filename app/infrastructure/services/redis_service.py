"""
Redis service implementation for interacting with Redis.

This module provides a clean Redis service implementation that follows the IRedisService
interface, allowing for proper dependency injection and testing.
"""

import logging

import redis.asyncio as redis
from fastapi import Request

from app.core.config.settings import Settings
from app.core.interfaces.services.redis_service_interface import IRedisService

logger = logging.getLogger(__name__)


class RedisService(IRedisService):
    """Redis service implementation that wraps aioredis.

    This service abstracts Redis operations and provides a consistent interface
    for working with Redis in the application, enabling clean architecture design.
    """

    def __init__(self, redis_client: redis.Redis):
        """Initialize the Redis service.

        Args:
            redis_client: Redis client instance to use
        """
        self._redis = redis_client
        logger.info("Redis service initialized")

    async def get(self, key: str) -> bytes | None:
        """Get a value from Redis.

        Args:
            key: The key to retrieve

        Returns:
            Optional[bytes]: Value if found, None otherwise
        """
        return await self._redis.get(key)

    async def set(
        self,
        key: str,
        value: str | bytes | int | float,
        ex: int | None = None,
        px: int | None = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool:
        """Set a key in Redis with optional expiration.

        Args:
            key: Key to set
            value: Value to set
            ex: Expiration in seconds
            px: Expiration in milliseconds
            nx: Only set if key does not exist
            xx: Only set if key exists

        Returns:
            bool: True if operation was successful
        """
        result = await self._redis.set(key, value, ex=ex, px=px, nx=nx, xx=xx)
        return result is not None

    async def delete(self, *keys: str) -> int:
        """Delete one or more keys.

        Args:
            *keys: Keys to delete

        Returns:
            int: Number of keys deleted
        """
        if not keys:
            return 0
        return await self._redis.delete(*keys)

    async def exists(self, *keys: str) -> int:
        """Check if one or more keys exist.

        Args:
            *keys: Keys to check

        Returns:
            int: Number of keys that exist
        """
        if not keys:
            return 0
        return await self._redis.exists(*keys)

    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on a key.

        Args:
            key: Key to set expiration on
            seconds: Expiration time in seconds

        Returns:
            bool: True if expiration was set
        """
        return await self._redis.expire(key, seconds)

    async def ttl(self, key: str) -> int:
        """Get time to live for a key.

        Args:
            key: Key to get TTL for

        Returns:
            int: TTL in seconds, -1 if no expiry, -2 if key doesn't exist
        """
        return await self._redis.ttl(key)

    async def keys(self, pattern: str) -> list[bytes]:
        """Get keys matching a pattern.

        Args:
            pattern: Pattern to match (e.g., "user:*")

        Returns:
            List[bytes]: List of matching keys
        """
        return await self._redis.keys(pattern)

    async def hget(self, name: str, key: str) -> bytes | None:
        """Get a value from a hash.

        Args:
            name: Hash name
            key: Key in the hash

        Returns:
            Optional[bytes]: Value if found, None otherwise
        """
        return await self._redis.hget(name, key)

    async def hset(self, name: str, key: str, value: str | bytes | int | float) -> int:
        """Set a key in a hash.

        Args:
            name: Hash name
            key: Key in the hash
            value: Value to set

        Returns:
            int: 1 if field was new, 0 if field was updated
        """
        return await self._redis.hset(name, key, value)

    async def hdel(self, name: str, *keys: str) -> int:
        """Delete keys from a hash.

        Args:
            name: Hash name
            *keys: Keys to delete

        Returns:
            int: Number of keys deleted
        """
        if not keys:
            return 0
        return await self._redis.hdel(name, *keys)

    async def hgetall(self, name: str) -> dict[bytes, bytes]:
        """Get all fields and values from a hash.

        Args:
            name: Hash name

        Returns:
            Dict[bytes, bytes]: All fields and values in the hash
        """
        return await self._redis.hgetall(name)

    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment a key by an amount.

        Args:
            key: Key to increment
            amount: Amount to increment by

        Returns:
            int: New value
        """
        return await self._redis.incr(key, amount)


async def get_redis_service(request: Request) -> IRedisService:
    """Dependency provider for Redis service.

    Args:
        request: FastAPI request

    Returns:
        IRedisService: Redis service implementation
    """
    # Use the redis client from app state
    if not hasattr(request.app.state, "redis"):
        # In case Redis is not configured, log warning
        logger.warning(
            "Redis client not found in app state, creating in-memory instance for testing"
        )

        # Create an in-memory Redis client for testing
        settings = Settings()
        redis_client = redis.Redis.from_url(
            settings.redis_url or "redis://localhost:6379/0", decode_responses=False
        )

        return RedisService(redis_client)

    return RedisService(request.app.state.redis)
