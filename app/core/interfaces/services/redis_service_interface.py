"""
Interface for Redis service to maintain a clean architecture boundary between
infrastructure and application layers.

This interface defines the contract that Redis service implementations must follow,
allowing the application layer to depend on abstractions rather than concrete implementations.
"""

from abc import ABC, abstractmethod


class IRedisService(ABC):
    """Interface for Redis operations.

    This interface ensures all Redis implementations provide consistent
    methods for interacting with Redis while maintaining separation of concerns
    in the clean architecture.
    """

    @abstractmethod
    async def get(self, key: str) -> bytes | None:
        """Get a value from Redis.

        Args:
            key: The key to retrieve

        Returns:
            Optional[bytes]: Value if found, None otherwise
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    async def delete(self, *keys: str) -> int:
        """Delete one or more keys.

        Args:
            *keys: Keys to delete

        Returns:
            int: Number of keys deleted
        """
        pass

    @abstractmethod
    async def exists(self, *keys: str) -> int:
        """Check if one or more keys exist.

        Args:
            *keys: Keys to check

        Returns:
            int: Number of keys that exist
        """
        pass

    @abstractmethod
    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on a key.

        Args:
            key: Key to set expiration on
            seconds: Expiration time in seconds

        Returns:
            bool: True if expiration was set
        """
        pass

    @abstractmethod
    async def ttl(self, key: str) -> int:
        """Get time to live for a key.

        Args:
            key: Key to get TTL for

        Returns:
            int: TTL in seconds, -1 if no expiry, -2 if key doesn't exist
        """
        pass

    @abstractmethod
    async def keys(self, pattern: str) -> list[bytes]:
        """Get keys matching a pattern.

        Args:
            pattern: Pattern to match (e.g., "user:*")

        Returns:
            List[bytes]: List of matching keys
        """
        pass

    @abstractmethod
    async def hget(self, name: str, key: str) -> bytes | None:
        """Get a value from a hash.

        Args:
            name: Hash name
            key: Key in the hash

        Returns:
            Optional[bytes]: Value if found, None otherwise
        """
        pass

    @abstractmethod
    async def hset(self, name: str, key: str, value: str | bytes | int | float) -> int:
        """Set a key in a hash.

        Args:
            name: Hash name
            key: Key in the hash
            value: Value to set

        Returns:
            int: 1 if field was new, 0 if field was updated
        """
        pass

    @abstractmethod
    async def hdel(self, name: str, *keys: str) -> int:
        """Delete keys from a hash.

        Args:
            name: Hash name
            *keys: Keys to delete

        Returns:
            int: Number of keys deleted
        """
        pass

    @abstractmethod
    async def hgetall(self, name: str) -> dict[bytes, bytes]:
        """Get all fields and values from a hash.

        Args:
            name: Hash name

        Returns:
            Dict[bytes, bytes]: All fields and values in the hash
        """
        pass

    @abstractmethod
    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment a key by an amount.

        Args:
            key: Key to increment
            amount: Amount to increment by

        Returns:
            int: New value
        """
        pass
