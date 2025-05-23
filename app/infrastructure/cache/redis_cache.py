"""
Redis Cache Implementation.

This module provides a Redis-based implementation of the CacheService
interface for efficient caching in a distributed environment.
"""

import asyncio
import json
import logging
import time  # Add missing time import for InMemoryFallback
from typing import Any, cast

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
    from redis.exceptions import RedisError
except ModuleNotFoundError:  # pragma: no cover – executed only in test env
    aioredis = None  # type: ignore

    class _InMemoryRedisShim:
        """Extremely small subset of the redis‑py asyncio API used in tests."""

        def __init__(self) -> None:
            self._store: dict[str, Any] = {}

        # Basic KV operations -------------------------------------------------
        async def get(self, key: str):
            return self._store.get(key)

        async def set(self, key: str, value: Any, ex: int | None = None) -> None:
            self._store[key] = value
            if ex is not None:
                # Implement TTL via naive time check stored alongside value
                # For tests we don't strictly need expiry behaviour, but we
                # record the deadline so that a future `get` could respect it
                # if desired.
                self._store[f"__ttl__:{key}"] = asyncio.get_event_loop().time() + ex

        async def exists(self, key: str) -> int:
            return 1 if key in self._store else 0

        async def incr(self, key: str) -> int:
            self._store[key] = int(self._store.get(key, 0)) + 1
            return int(self._store[key])

        async def expire(self, key: str, ttl: int) -> None:
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

from redis import asyncio as aioredis

# from app.core.interfaces.cache_service import CacheService # Incorrect import
from app.application.interfaces.services.cache_service import (  # Corrected import
    CacheService,
)

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings  # Corrected import

logger = logging.getLogger(__name__)


class RedisCache(CacheService):
    """
    Redis-based implementation of the cache service.

    This class provides a Redis-backed cache service implementation,
    suitable for production use in a distributed environment.
    """

    def __init__(self, connection_url: str | None = None):
        """
        Initialize RedisCache.

        Args:
            connection_url: Optional Redis connection URL. Defaults to settings.
        """
        settings = get_settings()
        # Use explicit fallback for testing
        default_redis_url = "redis://localhost:6379/1"
        self.redis_url = connection_url or getattr(settings, "REDIS_URL", default_redis_url)

        # Initialize client as None, will be lazily created
        self.redis_client = None

        # Try to connect immediately if Redis is available
        try:
            if aioredis:
                self.redis_client = aioredis.from_url(
                    self.redis_url, encoding="utf-8", decode_responses=True
                )
                logger.info(f"Connected to Redis at {self.redis_url}")
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}. Cache operations will fail safely.")
            self.redis_client = None

    async def get(self, key: str) -> Any:
        """
        Get a value from the cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        if not self.redis_client:
            return None

        try:
            value = await self.redis_client.get(key)

            if value is None:
                return None

            # Try to deserialize JSON
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                logger.warning(f"Failed to deserialize cache value for key: {key}")
                return None

        except Exception as e:
            logger.error(f"Error retrieving key {key} from cache: {e}")
            return None

    async def set(self, key: str, value: Any, expiration: int | None = 3600) -> bool:
        """
        Set a value in the cache with TTL.

        Args:
            key: Cache key
            value: Value to cache
            expiration: Time to live in seconds (default: 1 hour)

        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            return False

        try:
            # Serialize the value to JSON
            try:
                serialized_value = json.dumps(value)
            except TypeError as e:
                logger.error(f"Failed to serialize value for key {key}: {e}")
                return False

            # Handle the case when expiration is None
            if expiration is None:
                await self.redis_client.set(key, serialized_value)
            else:
                # Store with expiration time
                await self.redis_client.setex(key, expiration, serialized_value)
            return True

        except Exception as e:
            logger.error(f"Error setting key {key} in cache: {e}")
            return False

    async def delete(self, key: str) -> int:
        """
        Delete a value from the cache.

        Args:
            key: Cache key

        Returns:
            Number of keys deleted (0 or 1)
        """
        if not self.redis_client:
            return 0

        try:
            result = await self.redis_client.delete(key)
            return cast(int, result)
        except Exception as e:
            logger.error(f"Error deleting key {key} from cache: {e}")
            return 0

    # For test compatibility
    async def delete_bool(self, key: str) -> bool:
        """
        Delete a value from the cache, returning a boolean for test compatibility.

        Args:
            key: Cache key

        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            return False

        try:
            await self.redis_client.delete(key)
            return True  # Always return True on success per test expectations
        except Exception as e:
            logger.error(f"Error deleting key {key} from cache: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """
        Check if a key exists in the cache.

        Args:
            key: Cache key

        Returns:
            True if key exists, False otherwise
        """
        if not self.redis_client:
            return False

        try:
            result = await self.redis_client.exists(key)
            return bool(result)
        except Exception as e:
            logger.error(f"Error checking existence of key {key} in cache: {e}")
            return False

    async def increment(self, key: str, amount: int = 1) -> int:
        """
        Increment a counter in the cache.

        Args:
            key: Cache key
            amount: Amount to increment by (default: 1)

        Returns:
            New value after incrementing
        """
        if not self.redis_client:
            return 0

        try:
            result = await self.redis_client.incrby(key, amount)
            return cast(int, result)
        except Exception as e:
            logger.error(f"Error incrementing key {key} in cache: {e}")
            return 0  # Return 0 by default

    # Special method for compatibility with tests that expect None on error
    async def increment_with_none(self, key: str, amount: int = 1) -> int | None:
        """
        Increment a counter in the cache, returning None on errors for test compatibility.

        Args:
            key: Cache key
            amount: Amount to increment by (default: 1)

        Returns:
            New value or None on error
        """
        if not self.redis_client:
            return None

        try:
            result = await self.redis_client.incrby(key, amount)
            return cast(int, result)
        except Exception as e:
            logger.error(f"Error incrementing key {key} in cache: {e}")
            return None

    async def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration on a key.

        Args:
            key: Cache key
            seconds: TTL in seconds

        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            return False

        try:
            result = await self.redis_client.expire(key, seconds)
            return bool(result)
        except Exception as e:
            logger.error(f"Error setting expiration for key {key} in cache: {e}")
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
        if not self.redis_client:
            return -2

        try:
            result = await self.redis_client.ttl(key)
            return cast(int, result)
        except Exception as e:
            logger.error(f"Error getting TTL for key {key} in cache: {e}")
            return -2

    # Method for test compatibility
    async def get_ttl(self, key: str) -> int | None:
        """
        Get the remaining TTL for a key (for test compatibility).

        Args:
            key: Cache key

        Returns:
            TTL in seconds, or None if the key doesn't exist or has no TTL
        """
        if not self.redis_client:
            return None

        try:
            ttl = await self.redis_client.ttl(key)
            ttl_value = cast(int, ttl)
            # Redis returns -2 if the key doesn't exist, -1 if the key exists but has no TTL
            if ttl_value < 0:
                return None
            return ttl_value
        except Exception as e:
            logger.error(f"Error getting TTL for key {key} in cache: {e}")
            return None

    async def close(self) -> None:
        """
        Close the cache connection.

        This method releases any resources used by the cache service.
        """
        if not self.redis_client:
            return

        try:
            await self.redis_client.close()
            self.redis_client = None
            logger.info("Redis connection closed")
        except Exception as e:
            logger.error(f"Error closing Redis connection: {e}")


class InMemoryFallback:
    """
    In-memory fallback for Redis operations.

    This class provides an in-memory implementation of Redis commands
    for development and testing when Redis is unavailable.
    """

    def __init__(self):
        """Initialize the in-memory cache."""
        self._cache: dict[str, Any] = {}
        self._expirations: dict[str, float] = {}  # Store expiration timestamps

    async def _check_expired(self, key: str) -> bool:
        """Check if a key has expired and remove it if so."""
        if key in self._expirations and self._expirations[key] < time.time():
            if key in self._cache:
                del self._cache[key]
            del self._expirations[key]
            return True
        return False

    async def get(self, key: str) -> Any:
        """Get a value from the cache."""
        await self._check_expired(key)
        return self._cache.get(key)

    async def set(self, key: str, value: Any, ex: int | None = None) -> bool:
        """Set a value in the cache."""
        self._cache[key] = value
        if ex is not None:
            self._expirations[key] = time.time() + ex
        elif key in self._expirations:  # Remove expiration if ex is None
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
        await self._check_expired(key)
        return key in self._cache

    async def incr(self, key: str) -> int:
        """Increment a counter in the cache."""
        if await self._check_expired(key):
            self._cache[key] = 0  # Initialize if expired and accessed by incr

        current_value = self._cache.get(key, 0)
        if not isinstance(current_value, int):
            # Attempt conversion or handle error
            try:
                current_value = int(current_value)
            except (ValueError, TypeError):
                # Cannot increment non-integer value that isn't convertible
                # Redis behavior is to raise an error. We'll simulate by returning 0
                # and logging an error. A more strict simulation could raise ValueError.
                logger.error(
                    f"InMemoryFallback: Cannot increment non-integer value for key '{key}'"
                )
                return 0  # Or raise ValueError("value is not an integer or out of range")

        new_value = current_value + 1
        self._cache[key] = new_value
        # Incrementing removes TTL in Redis, simulate this
        if key in self._expirations:
            del self._expirations[key]
        return int(new_value)  # Explicitly ensure int return type

    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on a key."""
        if not await self.exists(key):  # Check existence and expiration
            return False
        self._expirations[key] = time.time() + seconds
        return True

    async def ttl(self, key: str) -> int:
        """Get the TTL for a key."""
        if await self._check_expired(key):
            return -2  # Key doesn't exist (because it expired)
        if key not in self._cache:
            return -2  # Key doesn't exist
        if key not in self._expirations:
            return -1  # Key exists but has no associated expiration

        remaining_seconds = self._expirations[key] - time.time()
        remaining_ttl = int(remaining_seconds)
        return max(0, remaining_ttl)  # Return 0 if expired but not yet cleaned up

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
    effective_redis_url = redis_url or getattr(settings, "REDIS_URL", "redis://localhost:6379/1")

    try:
        # Prepare connection options with reasonable defaults
        redis_ssl = getattr(settings, "REDIS_SSL", False)
        redis_connection_options = {"encoding": "utf-8", "decode_responses": True}
        if redis_ssl:
            redis_connection_options["ssl"] = True

        # Connect to Redis using the prepared options
        _redis_pool = await aioredis.from_url(effective_redis_url, **redis_connection_options)

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
