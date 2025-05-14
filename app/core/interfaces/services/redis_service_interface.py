from abc import abstractmethod
from typing import Protocol


class IRedisService(Protocol):
    """
    Interface for a Redis service, defining common Redis operations.
    This abstraction allows for different Redis client implementations
    (e.g., actual Redis, mock Redis for tests) to be used interchangeably.
    """

    @abstractmethod
    async def get(self, name: str) -> str | None:
        """Retrieve a value from Redis by key."""
        pass

    @abstractmethod
    async def set(
        self,
        name: str,
        value: str,
        expire: int | None = None,
        set_if_not_exists: bool | None = None,  # NX
        set_if_exists: bool | None = None,  # XX
    ) -> bool | None:
        """
        Set a value in Redis.

        Args:
            name: The key name.
            value: The value to set.
            expire: Optional expiration time in seconds.
            set_if_not_exists: (NX) Only set the key if it does not already exist.
            set_if_exists: (XX) Only set the key if it already exist.

        Returns:
            True if the set operation was successful, False or None otherwise based on options.
        """
        pass

    @abstractmethod
    async def delete(self, *names: str) -> int:
        """Delete one or more keys from Redis."""
        pass

    @abstractmethod
    async def exists(self, *names: str) -> int:
        """Check if one or more keys exist in Redis."""
        pass

    @abstractmethod
    async def ping(self) -> bool:
        """Ping the Redis server to check connectivity."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the Redis connection."""
        pass

    @abstractmethod
    async def get_client(self) -> any:  
        """Get the underlying Redis client instance."""
        pass

    # Add other common Redis operations as needed, e.g., for lists, hashes, sets
