"""
Redis Cache Service Implementation.

This module implements the CacheService interface using Redis as the
underlying technology for caching, rate limiting, and other high-performance
distributed operations.
"""

import json
from typing import Any

import redis.asyncio as redis  # Already correct, no change needed, but confirming
from redis.asyncio.connection import ConnectionPool
from redis.exceptions import RedisError

from app.application.interfaces.services.cache_service import CacheService
from app.core.utils.logging import get_logger

logger = get_logger(__name__)


class RedisCacheService(CacheService):
    """
    Redis implementation of the CacheService interface.

    This service provides caching, rate limiting, and other distributed operations
    using Redis as the backing technology.
    """

    def __init__(
        self,
        host: str,
        port: int,
        password: str | None = None,
        ssl: bool = False,
        prefix: str = "novamind:",
    ):
        """
        Initialize the Redis cache service.

        Args:
            host: Redis server hostname
            port: Redis server port
            password: Optional password for Redis authentication
            ssl: Whether to use SSL for Redis connection
            prefix: Key prefix to use for all Redis keys
        """
        self._prefix = prefix
        self._pool = ConnectionPool(
            host=host, port=port, password=password, ssl=ssl, decode_responses=True
        )
        self._redis: redis.Redis | None = None
        self._logger = logger

    async def _get_redis(self) -> redis.Redis:
        """
        Get a Redis client connection from the pool.

        Returns:
            A Redis client instance
        """
        if self._redis is None:
            self._redis = redis.Redis.from_pool(self._pool)
        return self._redis

    def _prefixed_key(self, key: str) -> str:
        """
        Add the service prefix to a key.

        Args:
            key: The original cache key

        Returns:
            The key with the service prefix prepended
        """
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> Any:
        """
        Get a value from the cache.

        Args:
            key: The cache key to retrieve

        Returns:
            The cached value, or None if not found

        Raises:
            Exception: If a Redis error occurs
        """
        prefixed_key = self._prefixed_key(key)

        try:
            client = await self._get_redis()
            value = await client.get(prefixed_key)

            if value is None:
                return None

            # Try to parse JSON, return raw string if not JSON
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value

        except RedisError as e:
            self._logger.error(f"Redis error in get operation: {e!s}")
            # Return None instead of raising - cache failures shouldn't break functionality
            return None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        """
        Set a value in the cache with optional TTL.

        Args:
            key: The cache key
            value: The value to cache
            ttl: Optional time-to-live in seconds

        Returns:
            True if successful, False otherwise

        Raises:
            Exception: If a Redis error occurs
        """
        prefixed_key = self._prefixed_key(key)

        # Convert non-string values to JSON
        if not isinstance(value, str):
            value = json.dumps(value)

        try:
            client = await self._get_redis()

            if ttl is not None:
                return await client.setex(prefixed_key, ttl, value)
            else:
                return await client.set(prefixed_key, value)

        except RedisError as e:
            self._logger.error(f"Redis error in set operation: {e!s}")
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete a value from the cache.

        Args:
            key: The cache key to delete

        Returns:
            True if key was deleted, False otherwise

        Raises:
            Exception: If a Redis error occurs
        """
        prefixed_key = self._prefixed_key(key)

        try:
            client = await self._get_redis()
            result = await client.delete(prefixed_key)
            return result > 0

        except RedisError as e:
            self._logger.error(f"Redis error in delete operation: {e!s}")
            return False

    async def increment(self, key: str, increment: int = 1) -> int:
        """
        Increment a counter in the cache.

        Args:
            key: The cache key to increment
            increment: The amount to increment by

        Returns:
            The new value after incrementing

        Raises:
            Exception: If a Redis error occurs
        """
        prefixed_key = self._prefixed_key(key)

        try:
            client = await self._get_redis()
            return await client.incrby(prefixed_key, increment)

        except RedisError as e:
            self._logger.error(f"Redis error in increment operation: {e!s}")
            # Return a high value to prevent rate limit bypassing on error
            return 999999

    async def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration time on a key.

        Args:
            key: The cache key
            seconds: Expiration time in seconds

        Returns:
            True if successful, False otherwise

        Raises:
            Exception: If a Redis error occurs
        """
        prefixed_key = self._prefixed_key(key)

        try:
            client = await self._get_redis()
            return await client.expire(prefixed_key, seconds)

        except RedisError as e:
            self._logger.error(f"Redis error in expire operation: {e!s}")
            return False

    async def get_hash(self, key: str) -> dict[str, Any]:
        """
        Get all fields in a hash.

        Args:
            key: The hash key

        Returns:
            Dictionary of hash fields and values

        Raises:
            Exception: If a Redis error occurs
        """
        prefixed_key = self._prefixed_key(key)

        try:
            client = await self._get_redis()
            result = await client.hgetall(prefixed_key)

            # Parse JSON values where possible
            parsed_result = {}
            for field, value in result.items():
                try:
                    parsed_result[field] = json.loads(value)
                except json.JSONDecodeError:
                    parsed_result[field] = value

            return parsed_result

        except RedisError as e:
            self._logger.error(f"Redis error in get_hash operation: {e!s}")
            return {}

    async def set_hash(self, key: str, values: dict[str, Any], ttl: int | None = None) -> bool:
        """
        Set multiple fields in a hash.

        Args:
            key: The hash key
            values: Dictionary of field/value pairs to set
            ttl: Optional time-to-live in seconds

        Returns:
            True if successful, False otherwise

        Raises:
            Exception: If a Redis error occurs
        """
        prefixed_key = self._prefixed_key(key)

        # Convert non-string values to JSON
        json_values = {}
        for field, value in values.items():
            if not isinstance(value, str):
                json_values[field] = json.dumps(value)
            else:
                json_values[field] = value

        try:
            client = await self._get_redis()

            # Use pipeline for atomicity
            pipeline = client.pipeline()
            pipeline.hmset(prefixed_key, json_values)

            if ttl is not None:
                pipeline.expire(prefixed_key, ttl)

            await pipeline.execute()
            return True

        except RedisError as e:
            self._logger.error(f"Redis error in set_hash operation: {e!s}")
            return False

    async def exists(self, key: str) -> bool:
        """
        Check if a key exists in the cache.

        Args:
            key: Cache key

        Returns:
            True if key exists, False otherwise
        """
        prefixed_key = self._prefixed_key(key)

        try:
            client = await self._get_redis()
            result = await client.exists(prefixed_key)
            return result > 0

        except RedisError as e:
            self._logger.error(f"Redis error in exists operation: {e!s}")
            return False

    async def ttl(self, key: str) -> int:
        """
        Get the TTL for a key.

        Args:
            key: Cache key

        Returns:
            TTL in seconds, -1 if key exists but has no TTL,
            -2 if key doesn't exist
        """
        prefixed_key = self._prefixed_key(key)

        try:
            client = await self._get_redis()
            return await client.ttl(prefixed_key)

        except RedisError as e:
            self._logger.error(f"Redis error in ttl operation: {e!s}")
            return -2  # Same as Redis behavior for non-existent keys

    async def close(self) -> None:
        """
        Close the cache connection.

        This method should release any resources used by the cache service.
        """
        if self._redis is not None:
            try:
                await self._redis.close()
                await self._pool.disconnect()
                self._redis = None

            except RedisError as e:
                self._logger.error(f"Redis error in close operation: {e!s}")
