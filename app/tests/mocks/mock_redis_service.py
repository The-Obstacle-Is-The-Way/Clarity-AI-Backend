"""Mock Redis Service for testing.

This module provides a mock implementation of the Redis service
for testing, avoiding the need for a real Redis instance.
Implements the IRedisService interface with full LSP compliance.
"""

import json
import logging
from collections.abc import Set as AbcSet
from typing import Any

from app.core.interfaces.services.redis_service_interface import IRedisService

logger = logging.getLogger(__name__)


class MockRedisService(IRedisService):
    """
    Mock implementation of IRedisService for testing.

    This implementation stores all data in memory and provides
    the same interface as the real Redis service, ensuring full
    Liskov Substitution Principle compliance.
    """

    def __init__(self) -> None:
        """Initialize the mock Redis service."""
        self._data: dict[str, Any] = {}
        self._expiry: dict[str, int] = {}  # TTL in seconds
        self._hashes: dict[str, dict[str, Any]] = {}
        logger.info("Initialized MockRedisService")

    async def get(self, key: str) -> bytes | None:
        """
        Get a value from Redis.

        Args:
            key: The key to retrieve

        Returns:
            The stored value as bytes, or None if key doesn't exist
        """
        logger.debug(f"MockRedisService.get({key})")
        value = self._data.get(key)
        if value is None:
            return None
        if isinstance(value, str):
            return value.encode('utf-8')
        elif isinstance(value, bytes):
            return value
        else:
            return str(value).encode('utf-8')

    async def set(
        self,
        key: str,
        value: str | bytes | int | float,
        ex: int | None = None,
        px: int | None = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool:
        """
        Set a key in Redis with optional expiration.

        Args:
            key: Key to set
            value: Value to set
            ex: Expiration in seconds
            px: Expiration in milliseconds
            nx: Only set if key does not exist
            xx: Only set if key exists

        Returns:
            True if operation was successful
        """
        value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
        logger.debug(f"MockRedisService.set({key}, {value_str}, ex={ex}, px={px}, nx={nx}, xx={xx})")
        
        # Handle nx and xx conditions
        key_exists = key in self._data
        if nx and key_exists:
            return False
        if xx and not key_exists:
            return False
        
        self._data[key] = value
        
        # Handle expiration
        if ex is not None:
            self._expiry[key] = ex
        elif px is not None:
            self._expiry[key] = px // 1000  # Convert milliseconds to seconds
        
        return True

    async def delete(self, *keys: str) -> int:
        """
        Delete one or more keys.

        Args:
            *keys: Keys to delete

        Returns:
            Number of keys deleted
        """
        logger.debug(f"MockRedisService.delete({keys})")
        deleted_count = 0
        for key in keys:
            if key in self._data:
                del self._data[key]
                if key in self._expiry:
                    del self._expiry[key]
                deleted_count += 1
        return deleted_count

    async def exists(self, *keys: str) -> int:
        """
        Check if one or more keys exist.

        Args:
            *keys: Keys to check

        Returns:
            Number of keys that exist
        """
        logger.debug(f"MockRedisService.exists({keys})")
        return sum(1 for key in keys if key in self._data)

    async def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration on a key.

        Args:
            key: Key to set expiration on
            seconds: Expiration time in seconds

        Returns:
            True if expiration was set
        """
        logger.debug(f"MockRedisService.expire({key}, {seconds})")
        if key in self._data:
            self._expiry[key] = seconds
            return True
        return False

    async def ttl(self, key: str) -> int:
        """
        Get time to live for a key.

        Args:
            key: Key to get TTL for

        Returns:
            TTL in seconds, -1 if no expiry, -2 if key doesn't exist
        """
        logger.debug(f"MockRedisService.ttl({key})")
        if key not in self._data:
            return -2
        return self._expiry.get(key, -1)

    async def keys(self, pattern: str) -> list[bytes]:
        """
        Get keys matching a pattern.

        Args:
            pattern: Pattern to match (e.g., "user:*")

        Returns:
            List of matching keys as bytes
        """
        logger.debug(f"MockRedisService.keys({pattern})")
        import fnmatch
        matching_keys = []
        for key in self._data.keys():
            if fnmatch.fnmatch(key, pattern):
                matching_keys.append(key.encode('utf-8'))
        return matching_keys

    async def hget(self, name: str, key: str) -> bytes | None:
        """
        Get a value from a hash.

        Args:
            name: Hash name
            key: Key in the hash

        Returns:
            Value if found as bytes, None otherwise
        """
        logger.debug(f"MockRedisService.hget({name}, {key})")
        if name not in self._hashes:
            return None
        value = self._hashes[name].get(key)
        if value is None:
            return None
        if isinstance(value, str):
            return value.encode('utf-8')
        elif isinstance(value, bytes):
            return value
        else:
            return str(value).encode('utf-8')

    async def hset(self, name: str, key: str, value: str | bytes | int | float) -> int:
        """
        Set a key in a hash.

        Args:
            name: Hash name
            key: Key in the hash
            value: Value to set

        Returns:
            1 if field was new, 0 if field was updated
        """
        value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
        logger.debug(f"MockRedisService.hset({name}, {key}, {value_str})")
        if name not in self._hashes:
            self._hashes[name] = {}
        
        is_new = key not in self._hashes[name]
        self._hashes[name][key] = value
        return 1 if is_new else 0

    async def hdel(self, name: str, *keys: str) -> int:
        """
        Delete keys from a hash.

        Args:
            name: Hash name
            *keys: Keys to delete

        Returns:
            Number of keys deleted
        """
        logger.debug(f"MockRedisService.hdel({name}, {keys})")
        if name not in self._hashes:
            return 0
        
        deleted_count = 0
        for key in keys:
            if key in self._hashes[name]:
                del self._hashes[name][key]
                deleted_count += 1
        return deleted_count

    async def hgetall(self, name: str) -> dict[bytes, bytes]:
        """
        Get all fields and values from a hash.

        Args:
            name: Hash name

        Returns:
            All fields and values in the hash as bytes
        """
        logger.debug(f"MockRedisService.hgetall({name})")
        if name not in self._hashes:
            return {}
        
        result = {}
        for key, value in self._hashes[name].items():
            key_bytes = key.encode('utf-8') if isinstance(key, str) else key
            if isinstance(value, str):
                value_bytes = value.encode('utf-8')
            elif isinstance(value, bytes):
                value_bytes = value
            else:
                value_bytes = str(value).encode('utf-8')
            result[key_bytes] = value_bytes
        return result

    async def incr(self, key: str, amount: int = 1) -> int:
        """
        Increment a key by an amount.

        Args:
            key: Key to increment
            amount: Amount to increment by

        Returns:
            New value
        """
        logger.debug(f"MockRedisService.incr({key}, {amount})")
        if key not in self._data:
            self._data[key] = 0
        current_value = self._data[key]
        if not isinstance(current_value, int):
            raise ValueError("Value is not an integer")
        new_value = current_value + amount
        self._data[key] = new_value
        return new_value

    # Additional helper methods for testing
    async def clear(self) -> None:
        """
        Clear all data (testing helper).
        """
        logger.debug("MockRedisService.clear()")
        self._data.clear()
        self._expiry.clear()
        self._hashes.clear()

    def _get_data(self) -> dict[str, Any]:
        """
        Get all data (testing helper).

        Returns:
            Copy of internal data dictionary
        """
        return self._data.copy()

    def _get_hashes(self) -> dict[str, dict[str, Any]]:
        """
        Get all hash data (testing helper).

        Returns:
            Copy of internal hash data
        """
        return self._hashes.copy()
