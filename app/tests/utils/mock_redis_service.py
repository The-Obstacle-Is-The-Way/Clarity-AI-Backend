"""
Mock Redis Service for Tests

This module provides a mock implementation of the IRedisService interface
for testing purposes, allowing tests to run without an actual Redis connection.
"""

from typing import Any
from unittest.mock import AsyncMock

from app.core.interfaces.services.redis_service_interface import IRedisService


class MockRedisService(IRedisService):
    """
    Mock implementation of IRedisService for testing.

    This implementation simulates Redis operations using in-memory
    data structures, allowing tests to run without Redis dependencies.
    """

    def __init__(self):
        """Initialize the mock Redis service with empty data store."""
        self._data: dict[str, bytes] = {}
        self._hashes: dict[str, dict[str, bytes]] = {}
        self._expires: dict[str, int] = {}
        self._client = AsyncMock()

    async def get(self, key: str) -> bytes | None:
        """Retrieve a value from the mock Redis by key."""
        value = self._data.get(key)
        if value is None:
            return None
        return value

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
        Set a value in the mock Redis.

        Args:
            key: The key name
            value: The value to set
            ex: Optional expiration time in seconds
            px: Optional expiration time in milliseconds
            nx: Only set if key doesn't exist
            xx: Only set if key exists

        Returns:
            True if successful, False otherwise
        """
        if nx and key in self._data:
            return False
        if xx and key not in self._data:
            return False

        # Convert value to bytes
        if isinstance(value, str):
            self._data[key] = value.encode("utf-8")
        elif isinstance(value, bytes):
            self._data[key] = value
        else:
            self._data[key] = str(value).encode("utf-8")

        # Handle expiration
        if ex is not None:
            self._expires[key] = ex
        elif px is not None:
            self._expires[key] = px // 1000  # Convert milliseconds to seconds

        return True

    async def delete(self, *keys: str) -> int:
        """
        Delete one or more keys from mock Redis.

        Args:
            *keys: One or more key names to delete

        Returns:
            Number of keys that were deleted
        """
        count = 0
        for key in keys:
            if key in self._data:
                del self._data[key]
                if key in self._expires:
                    del self._expires[key]
                count += 1
        return count

    async def exists(self, *keys: str) -> int:
        """
        Check if one or more keys exist in mock Redis.

        Args:
            *keys: One or more keys to check

        Returns:
            Number of keys that exist
        """
        return sum(1 for key in keys if key in self._data)

    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on a key."""
        if key in self._data:
            self._expires[key] = seconds
            return True
        return False

    async def ttl(self, key: str) -> int:
        """Get time to live for a key."""
        if key not in self._data:
            return -2  # Key doesn't exist
        if key not in self._expires:
            return -1  # No expiry set
        return self._expires[key]

    async def keys(self, pattern: str) -> list[bytes]:
        """Get keys matching a pattern."""
        import fnmatch

        matching_keys = []
        for key in self._data.keys():
            if fnmatch.fnmatch(key, pattern):
                matching_keys.append(key.encode("utf-8"))
        return matching_keys

    async def hget(self, name: str, key: str) -> bytes | None:
        """Get a value from a hash."""
        if name not in self._hashes:
            return None
        return self._hashes[name].get(key)

    async def hset(self, name: str, key: str, value: str | bytes | int | float) -> int:
        """Set a key in a hash."""
        if name not in self._hashes:
            self._hashes[name] = {}

        # Convert value to bytes
        if isinstance(value, str):
            bytes_value = value.encode("utf-8")
        elif isinstance(value, bytes):
            bytes_value = value
        else:
            bytes_value = str(value).encode("utf-8")

        was_new = key not in self._hashes[name]
        self._hashes[name][key] = bytes_value
        return 1 if was_new else 0

    async def hdel(self, name: str, *keys: str) -> int:
        """Delete keys from a hash."""
        if name not in self._hashes:
            return 0

        count = 0
        for key in keys:
            if key in self._hashes[name]:
                del self._hashes[name][key]
                count += 1

        # Clean up empty hash
        if not self._hashes[name]:
            del self._hashes[name]

        return count

    async def hgetall(self, name: str) -> dict[bytes, bytes]:
        """Get all fields and values from a hash."""
        if name not in self._hashes:
            return {}

        result = {}
        for key, value in self._hashes[name].items():
            result[key.encode("utf-8")] = value
        return result

    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment a key by an amount."""
        current_value = self._data.get(key, b"0")
        try:
            current_int = int(current_value.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            current_int = 0

        new_value = current_int + amount
        self._data[key] = str(new_value).encode("utf-8")
        return new_value

    async def ping(self) -> bool:
        """
        Ping the mock Redis server to check connectivity.

        Returns:
            Always True for mock implementation
        """
        return True

    async def close(self) -> None:
        """Close the mock Redis connection (no-op)."""
        pass

    async def get_client(self) -> Any:
        """
        Get the underlying Redis client instance.

        Returns:
            The mock client
        """
        return self._client


def create_mock_redis_service() -> IRedisService:
    """
    Factory function to create a mock Redis service.

    Returns:
        A new instance of MockRedisService
    """
    return MockRedisService()
