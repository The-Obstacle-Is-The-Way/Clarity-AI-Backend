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
        self._data: dict[str, str] = {}
        self._client = AsyncMock()
    
    async def get(self, name: str) -> str | None:
        """Retrieve a value from the mock Redis by key."""
        return self._data.get(name)
        
    async def set(
        self,
        name: str,
        value: str,
        expire: int | None = None,
        set_if_not_exists: bool | None = None,
        set_if_exists: bool | None = None,
    ) -> bool | None:
        """
        Set a value in the mock Redis.
        
        Args:
            name: The key name
            value: The value to set
            expire: Optional expiration time in seconds (not implemented in mock)
            set_if_not_exists: (NX) Only set if key doesn't exist
            set_if_exists: (XX) Only set if key exists
            
        Returns:
            True if successful, False or None otherwise based on options
        """
        if set_if_not_exists and name in self._data:
            return None
        if set_if_exists and name not in self._data:
            return None
            
        self._data[name] = value
        # Mock doesn't implement expiration
        return True
        
    async def delete(self, *names: str) -> int:
        """
        Delete one or more keys from mock Redis.
        
        Args:
            *names: One or more key names to delete
            
        Returns:
            Number of keys that were deleted
        """
        count = 0
        for name in names:
            if name in self._data:
                del self._data[name]
                count += 1
        return count
        
    async def exists(self, *names: str) -> int:
        """
        Check if one or more keys exist in mock Redis.
        
        Args:
            *names: One or more keys to check
            
        Returns:
            Number of keys that exist
        """
        return sum(1 for name in names if name in self._data)
        
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
