# -*- coding: utf-8 -*-
"""
Cache Service Interface.

This module defines the interface for cache services,
allowing for different implementations (Redis, in-memory, etc.)
while maintaining a consistent API.
"""

import abc
from typing import Any, Dict, List, Optional, Union


class CacheService(abc.ABC):
    """
    Abstract interface for cache services.
    
    This interface defines the methods that all cache service
    implementations must provide, ensuring consistent behavior
    regardless of the underlying technology.
    """
    
    @abc.abstractmethod
    async def get(self, key: str) -> Any:
        """
        Get a value from the cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        pass
        
    @abc.abstractmethod
    async def set(
        self, 
        key: str, 
        value: Any, 
        expiration: Optional[int] = None
    ) -> bool:
        """
        Set a value in the cache.
        
        Args:
            key: Cache key
            value: Value to cache
            expiration: Optional TTL in seconds
            
        Returns:
            True if successful, False otherwise
        """
        pass
        
    @abc.abstractmethod
    async def delete(self, key: str) -> int:
        """
        Delete a value from the cache.
        
        Args:
            key: Cache key
            
        Returns:
            Number of keys deleted (0 or 1)
        """
        pass
        
    @abc.abstractmethod
    async def exists(self, key: str) -> bool:
        """
        Check if a key exists in the cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if key exists, False otherwise
        """
        pass
        
    @abc.abstractmethod
    async def increment(self, key: str) -> int:
        """
        Increment a counter in the cache.
        
        If the key doesn't exist, it's initialized to 0 before incrementing.
        
        Args:
            key: Cache key
            
        Returns:
            New value after incrementing
        """
        pass
        
    @abc.abstractmethod
    async def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration on a key.
        
        Args:
            key: Cache key
            seconds: TTL in seconds
            
        Returns:
            True if successful, False otherwise
        """
        pass
        
    @abc.abstractmethod
    async def ttl(self, key: str) -> int:
        """
        Get the TTL for a key.
        
        Args:
            key: Cache key
            
        Returns:
            TTL in seconds, -1 if key exists but has no TTL,
            -2 if key doesn't exist
        """
        pass
        
    @abc.abstractmethod
    async def close(self) -> None:
        """
        Close the cache connection.
        
        This method should release any resources used by the cache service.
        """
        pass