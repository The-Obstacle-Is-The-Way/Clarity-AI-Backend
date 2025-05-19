"""
Mock Redis Service for testing.

This module provides a mock implementation of the Redis service
for testing, avoiding the need for a real Redis instance.
"""

from typing import Any, Dict, List, Optional, Set, Union
import logging

# Attempt to import the interface, provide a fallback if not found
try:
    from app.infrastructure.services.redis.redis_service import RedisService
except ImportError:
    # Define a minimal abstract base class as fallback
    from abc import ABC, abstractmethod

    class RedisService(ABC):
        """Fallback abstract base class if real interface is not found."""

        @abstractmethod
        async def get(self, key: str) -> Any:
            """Get value for key."""
            pass

        @abstractmethod
        async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
            """Set key to value with optional expiration."""
            pass

        @abstractmethod
        async def delete(self, key: str) -> bool:
            """Delete key."""
            pass


try:
    from app.infrastructure.logging.logger import get_logger

    logger = get_logger(__name__)
except ImportError:
    # Simple logger fallback
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)


class MockRedisService(RedisService):
    """
    Mock implementation of RedisService for testing.

    This implementation stores all data in memory and provides
    the same interface as the real Redis service.
    """

    def __init__(self):
        """Initialize the mock Redis service."""
        self._data: Dict[str, Any] = {}
        self._expiry: Dict[str, int] = {}  # TTL in seconds
        logger.info("Initialized MockRedisService")

    async def get(self, key: str) -> Any:
        """
        Get value for key.

        Args:
            key: The key to get

        Returns:
            The value or None if key doesn't exist
        """
        logger.debug(f"MockRedisService.get({key})")
        return self._data.get(key)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set key to value with optional expiration.

        Args:
            key: The key to set
            value: The value to set
            ttl: Optional time-to-live in seconds

        Returns:
            True if successful
        """
        logger.debug(f"MockRedisService.set({key}, {value}, ttl={ttl})")
        self._data[key] = value
        if ttl is not None:
            self._expiry[key] = ttl
        return True

    async def delete(self, key: str) -> bool:
        """
        Delete key.

        Args:
            key: The key to delete

        Returns:
            True if key existed and was deleted, False otherwise
        """
        logger.debug(f"MockRedisService.delete({key})")
        if key in self._data:
            del self._data[key]
            if key in self._expiry:
                del self._expiry[key]
            return True
        return False

    async def exists(self, key: str) -> bool:
        """
        Check if key exists.

        Args:
            key: The key to check

        Returns:
            True if key exists, False otherwise
        """
        logger.debug(f"MockRedisService.exists({key})")
        return key in self._data

    async def expire(self, key: str, ttl: int) -> bool:
        """
        Set expiration for key.

        Args:
            key: The key to set expiration for
            ttl: Time-to-live in seconds

        Returns:
            True if successful, False if key doesn't exist
        """
        logger.debug(f"MockRedisService.expire({key}, {ttl})")
        if key in self._data:
            self._expiry[key] = ttl
            return True
        return False

    async def ttl(self, key: str) -> int:
        """
        Get remaining time-to-live for key.

        Args:
            key: The key to get TTL for

        Returns:
            TTL in seconds, -1 if key exists but has no TTL, -2 if key doesn't exist
        """
        logger.debug(f"MockRedisService.ttl({key})")
        if key not in self._data:
            return -2
        return self._expiry.get(key, -1)

    async def incr(self, key: str) -> int:
        """
        Increment value of key by 1.

        Args:
            key: The key to increment

        Returns:
            New value after increment
        """
        logger.debug(f"MockRedisService.incr({key})")
        if key not in self._data:
            self._data[key] = 0
        if not isinstance(self._data[key], int):
            raise ValueError("Value is not an integer")
        self._data[key] += 1
        return self._data[key]

    async def decr(self, key: str) -> int:
        """
        Decrement value of key by 1.

        Args:
            key: The key to decrement

        Returns:
            New value after decrement
        """
        logger.debug(f"MockRedisService.decr({key})")
        if key not in self._data:
            self._data[key] = 0
        if not isinstance(self._data[key], int):
            raise ValueError("Value is not an integer")
        self._data[key] -= 1
        return self._data[key]

    async def hset(self, key: str, field: str, value: Any) -> int:
        """
        Set field in hash stored at key to value.

        Args:
            key: The key of the hash
            field: The field to set
            value: The value to set

        Returns:
            1 if field is new, 0 if field already existed
        """
        logger.debug(f"MockRedisService.hset({key}, {field}, {value})")
        if key not in self._data:
            self._data[key] = {}
        if not isinstance(self._data[key], dict):
            raise ValueError("Key exists but is not a hash")
        is_new = field not in self._data[key]
        self._data[key][field] = value
        return 1 if is_new else 0

    async def hget(self, key: str, field: str) -> Any:
        """
        Get value of field in hash stored at key.

        Args:
            key: The key of the hash
            field: The field to get

        Returns:
            The value or None if field or key doesn't exist
        """
        logger.debug(f"MockRedisService.hget({key}, {field})")
        if key not in self._data or not isinstance(self._data[key], dict):
            return None
        return self._data[key].get(field)

    async def hdel(self, key: str, field: str) -> int:
        """
        Delete field from hash stored at key.

        Args:
            key: The key of the hash
            field: The field to delete

        Returns:
            1 if field existed and was deleted, 0 otherwise
        """
        logger.debug(f"MockRedisService.hdel({key}, {field})")
        if key not in self._data or not isinstance(self._data[key], dict):
            return 0
        if field in self._data[key]:
            del self._data[key][field]
            return 1
        return 0

    async def clear(self) -> None:
        """
        Clear all data (testing helper).
        """
        logger.debug("MockRedisService.clear()")
        self._data.clear()
        self._expiry.clear()

    def _get_data(self) -> Dict[str, Any]:
        """
        Get all data (testing helper).

        Returns:
            Copy of internal data dictionary
        """
        return self._data.copy()
