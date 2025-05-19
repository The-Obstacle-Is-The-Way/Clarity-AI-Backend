"""
Redis service implementation.

This module implements the Redis service interface with a concrete implementation
using the redis-py library. It follows clean architecture principles by adhering
to the interface defined in the core layer.
"""

import json
import logging
from collections.abc import Set as AbcSet
from typing import Any

import redis.asyncio as redis_asyncio
from redis.asyncio.client import Redis

from app.core.interfaces.services.redis_service_interface import IRedisService

logger = logging.getLogger(__name__)


class RedisService(IRedisService):
    """
    Concrete implementation of the Redis service interface.

    This implementation uses the redis-py asyncio client to interact with Redis.
    It implements all methods defined in the IRedisService protocol.
    """

    def __init__(self, redis_client: Redis) -> None:
        """
        Initialize the Redis service with a client.

        Args:
            redis_client: An initialized asynchronous Redis client
        """
        self._redis = redis_client

    async def get(self, name: str) -> str | None:
        """
        Retrieve a value from Redis by key.

        Args:
            name: The key to retrieve

        Returns:
            The stored value, or None if key doesn't exist
        """
        try:
            value = await self._redis.get(name)
            return value.decode("utf-8") if value else None
        except Exception as e:
            logger.error(f"Redis get error for key '{name}': {e!s}")
            return None

    async def set(
        self,
        name: str,
        value: str,
        expire: int | None = None,
        set_if_not_exists: bool | None = None,
        set_if_exists: bool | None = None,
    ) -> bool | None:
        """
        Set a value in Redis.

        Args:
            name: The key name
            value: The value to set
            expire: Optional expiration time in seconds
            set_if_not_exists: (NX) Only set the key if it does not already exist
            set_if_exists: (XX) Only set the key if it already exists

        Returns:
            True if successful, False or None otherwise based on options
        """
        try:
            nx = set_if_not_exists if set_if_not_exists is not None else False
            xx = set_if_exists if set_if_exists is not None else False

            result = await self._redis.set(name, value, ex=expire, nx=nx, xx=xx)
            return (
                result is not None
            )  # Redis returns None if NX/XX conditions aren't met
        except Exception as e:
            logger.error(f"Redis set error for key '{name}': {e!s}")
            return None

    async def delete(self, *names: str) -> int:
        """
        Delete one or more keys from Redis.

        Args:
            *names: One or more key names to delete

        Returns:
            Number of keys that were deleted
        """
        try:
            if not names:
                return 0
            return await self._redis.delete(*names)
        except Exception as e:
            logger.error(f"Redis delete error for keys {names}: {e!s}")
            return 0

    async def exists(self, *names: str) -> int:
        """
        Check if one or more keys exist in Redis.

        Args:
            *names: One or more key names to check

        Returns:
            Number of keys that exist
        """
        try:
            if not names:
                return 0
            return await self._redis.exists(*names)
        except Exception as e:
            logger.error(f"Redis exists error for keys {names}: {e!s}")
            return 0

    async def ping(self) -> bool:
        """
        Ping the Redis server to check connectivity.

        Returns:
            True if the ping was successful, False otherwise
        """
        try:
            result = await self._redis.ping()
            return result
        except Exception as e:
            logger.error(f"Redis ping error: {e!s}")
            return False

    async def close(self) -> None:
        """
        Close the Redis connection.
        """
        try:
            await self._redis.close()
            logger.debug("Redis connection closed")
        except Exception as e:
            logger.error(f"Redis close error: {e!s}")

    async def get_client(self) -> Redis:
        """
        Get the underlying Redis client instance.

        Returns:
            The Redis client instance
        """
        return self._redis

    async def expire(self, name: str, time: int) -> bool:
        """
        Set a key's time to live in seconds.

        Args:
            name: The key name
            time: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        try:
            return await self._redis.expire(name, time)
        except Exception as e:
            logger.error(f"Redis expire error for key '{name}': {e!s}")
            return False

    async def ttl(self, name: str) -> int:
        """
        Get the time to live for a key in seconds.

        Args:
            name: The key name

        Returns:
            TTL in seconds, -1 if key exists but has no TTL, -2 if key doesn't exist
        """
        try:
            return await self._redis.ttl(name)
        except Exception as e:
            logger.error(f"Redis TTL error for key '{name}': {e!s}")
            return -2

    async def setex(self, name: str, time: int, value: str) -> bool:
        """
        Set the value and expiration of a key.

        Args:
            name: The key name
            time: Expiration time in seconds
            value: The value to set

        Returns:
            True if successful, False otherwise
        """
        try:
            result = await self._redis.setex(name, time, value)
            return result is not None
        except Exception as e:
            logger.error(f"Redis setex error for key '{name}': {e!s}")
            return False

    async def sadd(self, name: str, *values: str) -> int:
        """
        Add one or more members to a set.

        Args:
            name: The set name
            *values: One or more values to add to the set

        Returns:
            Number of elements added to the set
        """
        try:
            if not values:
                return 0
            return await self._redis.sadd(name, *values)
        except Exception as e:
            logger.error(f"Redis sadd error for set '{name}': {e!s}")
            return 0

    async def smembers(self, name: str) -> AbcSet[str]:
        """
        Get all members of a set.

        Args:
            name: The set name

        Returns:
            Set of all members
        """
        try:
            result = await self._redis.smembers(name)
            return {v.decode("utf-8") for v in result} if result else set()
        except Exception as e:
            logger.error(f"Redis smembers error for set '{name}': {e!s}")
            return set()

    async def srem(self, name: str, *values: str) -> int:
        """
        Remove one or more members from a set.

        Args:
            name: The set name
            *values: One or more values to remove from the set

        Returns:
            Number of elements removed from the set
        """
        try:
            if not values:
                return 0
            return await self._redis.srem(name, *values)
        except Exception as e:
            logger.error(f"Redis srem error for set '{name}': {e!s}")
            return 0

    async def hset(self, name: str, key: str, value: Any) -> int:
        """
        Set the value of a hash field.

        Args:
            name: The hash name
            key: The field name
            value: The field value

        Returns:
            1 if field is a new field in the hash and value was set, 0 otherwise
        """
        try:
            # Convert value to string if it's not already
            if not isinstance(value, (str, bytes)):
                value = json.dumps(value)
            return await self._redis.hset(name, key, value)
        except Exception as e:
            logger.error(f"Redis hset error for hash '{name}', field '{key}': {e!s}")
            return 0

    async def hget(self, name: str, key: str) -> str | None:
        """
        Get the value of a hash field.

        Args:
            name: The hash name
            key: The field name

        Returns:
            The value of the field, or None if field or hash doesn't exist
        """
        try:
            result = await self._redis.hget(name, key)
            return result.decode("utf-8") if result else None
        except Exception as e:
            logger.error(f"Redis hget error for hash '{name}', field '{key}': {e!s}")
            return None


def create_redis_service(redis_url: str) -> IRedisService:
    """
    Factory function to create a Redis service.

    Args:
        redis_url: Redis connection URL

    Returns:
        An initialized Redis service
    """
    pool = redis_asyncio.ConnectionPool.from_url(redis_url)
    client = redis_asyncio.Redis(connection_pool=pool)
    return RedisService(redis_client=client)
