"""
Redis Cache Implementation.

This module provides a Redis-based implementation of the CacheService
interface for efficient caching in a distributed environment.
"""

import asyncio
import json
import logging
from typing import Any

# ---------------------------------------------------------------------------
# Optional dependency handling
# ---------------------------------------------------------------------------
# `redis` is an optional runtime dependency that is NOT installed in the CI
# environment (and should never be required when the TESTING flag is set).  To
# keep import‑time failures from breaking the entire test discovery phase we
# lazily attempt to import the library and fall back to a minimal in‑memory
# shim when it isn't available.
#
# The shim only implements the very small surface area exercised by the code
# base: `get`, `set`, `exists`, `incr`, `expire`, and the awaited variants
# thereof.  It intentionally does **not** try to be feature‑complete.
# ---------------------------------------------------------------------------

try:
    import redis.asyncio as aioredis  # type: ignore
except ModuleNotFoundError:  # pragma: no cover – executed only in test env
    aioredis = None  # type: ignore

    class _InMemoryRedisShim:
        """Extremely small subset of the redis‑py asyncio API used in tests."""

        def __init__(self) -> None:
            self._store: dict[str, Any] = {}

        # Basic KV operations -------------------------------------------------
        async def get(self, key: str):
            return self._store.get(key)

        async def set(self, key: str, value: Any, ex: int | None = None):
            self._store[key] = value
            if ex is not None:
                # Implement TTL via naive time check stored alongside value
                # For tests we don't strictly need expiry behaviour, but we
                # record the deadline so that a future `get` could respect it
                # if desired.
                self._store[f"__ttl__:{key}"] = asyncio.get_event_loop().time() + ex

        async def exists(self, key: str):
            return 1 if key in self._store else 0

        async def incr(self, key: str):
            self._store[key] = int(self._store.get(key, 0)) + 1
            return self._store[key]

        async def expire(self, key: str, ttl: int):
            # Record TTL as for set(ex=...)
            self._store[f"__ttl__:{key}"] = asyncio.get_event_loop().time() + ttl

        # Connection helper --------------------------------------------------
        @classmethod
        async def from_url(cls, *_args, **_kwargs):
            return cls()

    # Expose the shim under the name we attempted to import so that the rest
    # of this module can remain unchanged.
    aioredis = _InMemoryRedisShim  # type: ignore

    # Mimic the attr layout of the real `redis.asyncio` module so that type
    # annotations like `aioredis.Redis` continue to resolve.
    aioredis.Redis = _InMemoryRedisShim  # type: ignore

from app.application.interfaces.services.cache_service import CacheService
from app.config.settings import get_settings

logger = logging.getLogger(__name__)


class RedisCache(CacheService):
    """
    Redis-based implementation of the cache service.
    
    This class provides a Redis-backed cache service implementation,
    suitable for production use in a distributed environment.
    """
    
    _client: aioredis.Redis | None = None
    _lock = asyncio.Lock()

    def __init__(self, connection_url: str | None = None):
        """
        Initialize RedisCache.

        Args:
            connection_url: Optional Redis connection URL. Defaults to settings.
        """
        settings = get_settings()
        # Use getattr for safer access with a fallback default for testing
        default_redis_url = "redis://localhost:6379/1" # Default test Redis DB
        effective_redis_url = getattr(settings, 'REDIS_URL', default_redis_url)
        self.redis_url = connection_url or effective_redis_url
        
        if not self.redis_url:
            # This path should ideally not be hit if defaults work
            logger.warning("Redis URL not configured and default failed. RedisCache will not connect.")
            self.redis_url = default_redis_url # Ensure there's always a fallback
        # Connection is established lazily in get_client
        
    async def initialize(self) -> None:
        """
        Initialize the Redis client.
        
        This method establishes a connection to the Redis server
        according to application settings.
        """
        if self._client is not None:
            return
            
        try:
            # Get Redis connection settings
            redis_ssl = getattr(self, "REDIS_SSL", False)
            
            # Prepare connection options
            redis_connection_options = {
                "encoding": "utf-8",
                "decode_responses": True
            }
            # Only add the 'ssl' argument if redis_ssl is explicitly True
            if redis_ssl:
                 redis_connection_options["ssl"] = True

            # Connect to Redis using the prepared options
            self._client = await aioredis.from_url(
                self.redis_url,
                **redis_connection_options
            )
            
            logger.info(f"Connected to Redis at {self.redis_url}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e!s}")
            # Fallback to an in-memory implementation for development
            self._client = InMemoryFallback()
            logger.warning("Using in-memory fallback for cache (not for production)")
            
    async def get(self, key: str) -> Any:
        """
        Get a value from the cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        if self._client is None:
            await self.initialize()
            
        try:
            value = await self._client.get(key)
            
            if value is None:
                return None
                
            # Try to deserialize JSON
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                # Return as is if not JSON
                return value
                
        except Exception as e:
            logger.error(f"Error retrieving key {key} from cache: {e!s}")
            return None
            
    async def set(
        self, 
        key: str, 
        value: Any, 
        expiration: int | None = None
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
        if self._client is None:
            await self.initialize()
            
        try:
            # Serialize complex objects to JSON
            if not isinstance(value, (str, int, float, bool)) and value is not None:
                value = json.dumps(value)
                
            # Set with expiration if provided
            if expiration is not None:
                await self._client.set(key, value, ex=expiration)
            else:
                await self._client.set(key, value)
                
            return True
            
        except Exception as e:
            logger.error(f"Error setting key {key} in cache: {e!s}")
            return False
            
    async def delete(self, key: str) -> int:
        """
        Delete a value from the cache.
        
        Args:
            key: Cache key
            
        Returns:
            Number of keys deleted (0 or 1)
        """
        if self._client is None:
            await self.initialize()
            
        try:
            return await self._client.delete(key)
        except Exception as e:
            logger.error(f"Error deleting key {key} from cache: {e!s}")
            return 0
            
    async def exists(self, key: str) -> bool:
        """
        Check if a key exists in the cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if key exists, False otherwise
        """
        if self._client is None:
            await self.initialize()
            
        try:
            return bool(await self._client.exists(key))
        except Exception as e:
            logger.error(f"Error checking if key {key} exists in cache: {e!s}")
            return False
            
    async def increment(self, key: str) -> int:
        """
        Increment a counter in the cache.
        
        If the key doesn't exist, it's initialized to 0 before incrementing.
        
        Args:
            key: Cache key
            
        Returns:
            New value after incrementing
        """
        if self._client is None:
            await self.initialize()
            
        try:
            return await self._client.incr(key)
        except Exception as e:
            logger.error(f"Error incrementing key {key} in cache: {e!s}")
            return 0
            
    async def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration on a key.
        
        Args:
            key: Cache key
            seconds: TTL in seconds
            
        Returns:
            True if successful, False otherwise
        """
        if self._client is None:
            await self.initialize()
            
        try:
            return bool(await self._client.expire(key, seconds))
        except Exception as e:
            logger.error(f"Error setting expiration for key {key} in cache: {e!s}")
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
        if self._client is None:
            await self.initialize()
            
        try:
            return await self._client.ttl(key)
        except Exception as e:
            logger.error(f"Error getting TTL for key {key} in cache: {e!s}")
            return -2
            
    async def close(self) -> None:
        """
        Close the cache connection.
        
        This method releases any resources used by the cache service.
        """
        if self._client is None:
            return
            
        try:
            await self._client.close()
            self._client = None
        except Exception as e:
            logger.error(f"Error closing Redis connection: {e!s}")


class InMemoryFallback:
    """
    In-memory fallback for Redis operations.
    
    This class provides an in-memory implementation of Redis commands
    for development and testing when Redis is unavailable.
    """
    
    def __init__(self):
        """Initialize the in-memory cache."""
        self._cache: dict[str, Any] = {}
        self._expirations: dict[str, float] = {} # Store expiration timestamps

    async def _check_expired(self, key: str):
        """Check if a key has expired and remove it if so."""
        if key in self._expirations and self._expirations[key] < time.time():
            if key in self._cache:
                del self._cache[key]
            del self._expirations[key]
            return True
        return False

    async def get(self, key: str) -> Any:
        if self._check_expired(key):
            return None
        return self._cache.get(key)
        
    async def set(self, key: str, value: Any, ex: int | None = None) -> bool:
        """Set a value in the cache."""
        self._cache[key] = value
        if ex is not None:
            self._expirations[key] = time.time() + ex
        elif key in self._expirations: # Remove expiration if ex is None
             del self._expirations[key]
        return True
        
    async def delete(self, key: str) -> int:
        """Delete a value from the cache."""
        deleted = 0
        if key in self._cache:
            del self._cache[key]
            deleted = 1
        if key in self._expirations:
            del self._expirations[key]
        return deleted
        
    async def exists(self, key: str) -> bool:
        """Check if a key exists in the cache."""
        if self._check_expired(key):
            return False
        return key in self._cache
        
    async def incr(self, key: str) -> int:
        """Increment a counter in the cache."""
        if self._check_expired(key):
             self._cache[key] = 0 # Initialize if expired and accessed by incr
        
        current_value = self._cache.get(key, 0)
        if not isinstance(current_value, int):
             # Attempt conversion or handle error
             try:
                 current_value = int(current_value)
             except (ValueError, TypeError):
                 # Cannot increment non-integer value that isn't convertible
                 # Redis behavior is to raise an error. We'll simulate by returning 0
                 # and logging an error. A more strict simulation could raise ValueError.
                 logger.error(f"InMemoryFallback: Cannot increment non-integer value for key '{key}'")
                 return 0 # Or raise ValueError("value is not an integer or out of range")

        new_value = current_value + 1
        self._cache[key] = new_value
        # Incrementing removes TTL in Redis, simulate this
        if key in self._expirations:
            del self._expirations[key]
        return new_value
        
    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on a key."""
        if not await self.exists(key): # Check existence and expiration
            return False
        self._expirations[key] = time.time() + seconds
        return True
        
    async def ttl(self, key: str) -> int:
        """Get the TTL for a key."""
        if self._check_expired(key):
            return -2 # Key doesn't exist (because it expired)
        if key not in self._cache:
            return -2 # Key doesn't exist
        if key not in self._expirations:
            return -1 # Key exists but has no associated expiration
        
        remaining_ttl = int(self._expirations[key] - time.time())
        return max(0, remaining_ttl) # Return 0 if expired but not yet cleaned up
        
    async def close(self) -> None:
        """Close the cache connection."""
        self._cache = {}
        self._expirations = {}
        logger.debug("InMemoryFallback closed (cleared).")

# Global Redis connection pool and cache instance for application-wide use
_redis_pool: aioredis.Redis | None = None
_cache_instance: RedisCache | None = None

async def get_cache_service() -> CacheService:
    """
    Get the global cache service instance.
    
    Initializes the service if it hasn't been already.
    
    Returns:
        CacheService: The initialized cache service instance (Redis or fallback).
    """
    global _cache_instance
    
    if _cache_instance is None:
        _cache_instance = RedisCache()
        await _cache_instance.initialize()
        
    return _cache_instance


async def initialize_redis_pool(redis_url: str | None = None) -> None:
    """
    Initialize the global Redis connection pool for application-wide use.
    
    Should be called during application startup to ensure Redis is properly configured
    before it's needed by various components.
    
    Args:
        redis_url: Optional Redis connection URL. Defaults to settings.
    """
    global _redis_pool
    
    if _redis_pool is not None:
        logger.info("Redis pool already initialized.")
        return
        
    # Get Redis connection settings
    settings = get_settings()
    effective_redis_url = redis_url or getattr(settings, 'REDIS_URL', "redis://localhost:6379/1")
    
    try:
        # Prepare connection options with reasonable defaults
        redis_ssl = getattr(settings, "REDIS_SSL", False)
        redis_connection_options = {
            "encoding": "utf-8",
            "decode_responses": True
        }
        if redis_ssl:
             redis_connection_options["ssl"] = True

        # Connect to Redis using the prepared options
        _redis_pool = await aioredis.from_url(
            effective_redis_url,
            **redis_connection_options
        )
        
        logger.info(f"Global Redis pool initialized at {effective_redis_url}")
        
    except Exception as e:
        logger.error(f"Failed to initialize Redis pool: {e!s}")
        # In production, this might be critical enough to re-raise
        # For development/testing, we can fallback to an in-memory implementation
        if getattr(settings, "ENVIRONMENT", "").lower() == "production":
            logger.critical("Redis connection failure in production environment")
            # Consider raising exception to prevent app startup with missing Redis
            # raise


async def close_redis_connection() -> None:
    """
    Close the global Redis connection pool.
    
    Should be called during application shutdown to ensure proper cleanup.
    """
    global _redis_pool
    
    if _redis_pool is not None:
        try:
            await _redis_pool.close()
            logger.info("Global Redis pool closed.")
        except Exception as e:
            logger.error(f"Error closing Redis pool: {e!s}")
        finally:
            _redis_pool = None