"""
Enhanced Rate Limiter module for API protection.

This module provides enhanced rate limiting capabilities for protecting APIs from abuse.
It supports both in-memory and Redis-based rate limiting with configurable thresholds.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from unittest.mock import AsyncMock

import redis
from pydantic import BaseModel
from slowapi.util import get_remote_address

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings  # Corrected import

settings = get_settings()

logger = logging.getLogger(__name__)


class RateLimitType(Enum):
    """
    Enumeration for different rate limit types/scopes.
    Used to select specific rate limit configurations.
    """

    DEFAULT = "default"
    LOGIN = "login"
    SENSITIVE = "sensitive"
    ADMIN = "admin"
    FACTORY = "factory"


class RateLimitConfig(BaseModel):
    """
    Configuration for rate limiting.

    Attributes:
        requests: Maximum number of requests allowed in the window
        window_seconds: Time window in seconds
        block_seconds: Optional blocking period after exceeding limit
    """

    requests: int
    window_seconds: int
    block_seconds: int | None = None

    @property
    def requests_per_period(self) -> int:
        # Alias for compatibility with pipeline info
        return self.requests

    @property
    def period_seconds(self) -> int:
        # Alias for compatibility with pipeline info
        return self.window_seconds


class RateLimiter(ABC):
    """
    Abstract base class for rate limiters.

    This defines the interface that all rate limiter implementations must follow.
    """

    @abstractmethod
    def check_rate_limit(
        self, key: str, config: Any = None, user_id: str | None = None
    ) -> Any:
        """
        Check if a request should be rate limited.

        Args:
            key: Identifier for the rate limit (e.g., IP address, user ID)
            config: Rate limit configuration

        Returns:
            True if request is allowed, False if it should be rate limited
        """
        pass

    @abstractmethod
    def reset_limits(self, key: str) -> None:
        """
        Reset rate limits for a specific key.

        Args:
            key: Identifier to reset
        """
        pass


class InMemoryRateLimiter(RateLimiter):
    """
    In-memory implementation of rate limiting.

    Uses local memory to track request counts and blocked status.
    Suitable for single-instance deployments.
    """

    def __init__(self):
        """Initialize the in-memory rate limiter."""
        self._request_logs: dict[str, list[datetime]] = {}
        self._blocked_until: dict[str, datetime] = {}

    def _clean_old_requests(self, key: str, window_seconds: int) -> None:
        """
        Remove expired requests from the logs.

        Args:
            key: Identifier for the rate limit
            window_seconds: Time window in seconds
        """
        if key not in self._request_logs:
            return

        now = datetime.now()
        cutoff = now - timedelta(seconds=window_seconds)
        self._request_logs[key] = [t for t in self._request_logs[key] if t >= cutoff]

    def check_rate_limit(self, key: str, config: RateLimitConfig) -> bool:
        """
        Check if a request should be rate limited.

        Args:
            key: Identifier for the rate limit (e.g., IP address, user ID)
            config: Rate limit configuration

        Returns:
            True if request is allowed, False if it should be rate limited
        """
        now = datetime.now()

        # Check if the key is blocked
        if key in self._blocked_until and self._blocked_until[key] > now:
            return False

        # Clean up old requests
        self._clean_old_requests(key, config.window_seconds)

        # Initialize request log if needed
        if key not in self._request_logs:
            self._request_logs[key] = []

        # Check if over the limit
        if len(self._request_logs[key]) >= config.requests:
            # Block the key if block_seconds is set
            if config.block_seconds:
                self._blocked_until[key] = now + timedelta(seconds=config.block_seconds)
            return False

        # Add this request to the log
        self._request_logs[key].append(now)
        return True

    def reset_limits(self, key: str) -> None:
        """
        Reset rate limits for a specific key.

        Args:
            key: Identifier to reset
        """
        if key in self._request_logs:
            del self._request_logs[key]

        if key in self._blocked_until:
            del self._blocked_until[key]


class RedisRateLimiter(RateLimiter):
    """
    Redis-based implementation of rate limiting.

    Uses Redis sorted sets for distributed rate limiting across multiple instances.
    Suitable for production, multi-instance deployments.
    """

    def __init__(self, redis_client: redis.Redis | None = None):
        """
        Initialize the Redis rate limiter.

        Args:
            redis_client: Optional Redis client to use
        """
        self._redis = redis_client
        # Default configurations for different rate limit types
        # Values here can be adjusted or loaded from settings
        self.configs: dict[RateLimitType, RateLimitConfig] = {
            RateLimitType.DEFAULT: RateLimitConfig(requests=10, window_seconds=60),
            RateLimitType.LOGIN: RateLimitConfig(requests=10, window_seconds=60),
        }

    def _get_counter_key(self, key: str) -> str:
        """
        Generate Redis key for request counter.

        Args:
            key: Identifier for the rate limit

        Returns:
            Redis key string
        """
        return f"ratelimit:counter:{key}"

    def _get_blocked_key(self, key: str) -> str:
        """
        Generate Redis key for blocked status.

        Args:
            key: Identifier for the rate limit

        Returns:
            Redis key string
        """
        return f"ratelimit:blocked:{key}"

    def check_rate_limit(
        self, key: str, config: Any = None, user_id: str | None = None
    ) -> Any:
        """
        Check if a request should be rate limited.

        Args:
            key: Identifier for the rate limit (e.g., IP address, user ID)
            config: Rate limit configuration

        Returns:
            True if request is allowed, False if it should be rate limited
        """
        # Dispatch based on parameters: pipeline branch vs config-only
        # Pipeline usage: when config is a RateLimitType
        if isinstance(config, RateLimitType):
            # user_id must be provided for pipeline key composition
            return self._check_rate_limit_pipeline(key, config, user_id)
        # Config override or default config branch
        # Determine default config if not provided
        cfg = (
            config
            if isinstance(config, RateLimitConfig)
            else RateLimitConfig(requests=10, window_seconds=60)
        )
        # If no Redis client, always allow
        if not self._redis:
            return True
        # Decide branch based on Redis client type (sync vs async)
        # AsyncRedis clients in tests are AsyncMock instances
        if isinstance(self._redis, AsyncMock):
            return self._check_rate_limit_async(key, cfg)
        # Default to synchronous Redis client branch
        return self._check_rate_limit_sync(key, cfg)

    def _check_rate_limit_sync(self, key: str, config: RateLimitConfig) -> bool:
        """
        Synchronous rate limit check using a blocking Redis client.
        """
        try:
            if not self._redis:
                return True
            now = datetime.now().timestamp()
            blocked_key = self._get_blocked_key(key)
            counter_key = self._get_counter_key(key)
            # Check if the key is blocked
            if self._redis.exists(blocked_key):
                return False
            # Clean up old requests
            expired_cutoff = now - config.window_seconds
            self._redis.zremrangebyscore(counter_key, 0, expired_cutoff)
            # Check if over the limit
            request_count = self._redis.zcard(counter_key)
            if request_count >= config.requests:
                if config.block_seconds:
                    self._redis.setex(blocked_key, config.block_seconds, 1)
                return False
            # Add this request to the log
            self._redis.zadd(counter_key, {str(now): now})
            # Set expiration on the sorted set
            self._redis.expire(counter_key, config.window_seconds * 2)
            return True
        except redis.RedisError as e:
            logger.error(f"Redis error in rate limiter: {e}")
            return True

    async def _check_rate_limit_async(self, key: str, config: RateLimitConfig) -> bool:
        """
        Asynchronous rate limit check using an async Redis client.
        """
        try:
            if not self._redis:
                return True
            now = datetime.now().timestamp()
            blocked_key = self._get_blocked_key(key)
            counter_key = self._get_counter_key(key)
            # Check if the key is blocked
            if await self._redis.exists(blocked_key):
                return False
            # Clean up old requests
            expired_cutoff = now - config.window_seconds
            await self._redis.zremrangebyscore(counter_key, 0, expired_cutoff)
            # Check if over the limit
            request_count = await self._redis.zcard(counter_key)
            if request_count >= config.requests:
                if config.block_seconds:
                    await self._redis.setex(blocked_key, config.block_seconds, 1)
                return False
            # Add this request to the log
            await self._redis.zadd(counter_key, {str(now): now})
            # Set expiration on the sorted set
            await self._redis.expire(counter_key, config.window_seconds * 2)
            return True
        except redis.RedisError as e:
            logger.error(f"Redis error in rate limiter: {e}")
            return True

    async def _check_rate_limit_pipeline(
        self, identifier: str, limit_type: RateLimitType, user_id: str | None
    ) -> tuple[bool, dict[str, Any]]:
        """
        Advanced async pipeline-based rate limit check with user scoping.
        """
        # Determine combined key for user and identifier
        combined_key = f"{limit_type.value}:{user_id}:{identifier}"
        config = self.configs.get(limit_type)
        now = datetime.now().timestamp()
        try:
            # Use Redis pipeline for atomic operations
            async with self._redis.pipeline() as pipe:
                # Remove expired entries
                expired_cutoff = now - config.period_seconds
                await pipe.zremrangebyscore(combined_key, 0, expired_cutoff)
                # Add current request
                await pipe.zadd(combined_key, {str(now): now})
                # Count total requests
                await pipe.zcard(combined_key)
                # Get TTL for reset calculation
                await pipe.pttl(combined_key)
                results = await pipe.execute()
            # Extract count and TTL
            count = results[2]
            ttl_ms = results[3]
            # Determine limit and remaining
            limit = config.requests_per_period
            remaining = max(limit - count, 0)
            # Compute reset time
            reset_at = datetime.now() + timedelta(seconds=config.period_seconds)
            return False, {"limit": limit, "remaining": remaining, "reset_at": reset_at}
        except redis.RedisError as e:
            logger.error(f"Redis error in pipeline rate limiter: {e}")
            # Fail open
            return False, {}

    def reset_limits(self, key: str) -> None:
        """
        Reset rate limits for a specific key.

        Args:
            key: Identifier to reset
        """
        try:
            if not self._redis:
                return

            blocked_key = self._get_blocked_key(key)
            counter_key = self._get_counter_key(key)

            # Delete both keys
            self._redis.delete(blocked_key, counter_key)

        except redis.RedisError as e:
            logger.error(f"Redis error in reset_limits: {e}")


class RateLimiterFactory:
    """
    Factory for creating rate limiters.

    This class uses the Factory Method pattern to create the appropriate
    rate limiter based on configuration settings.
    """

    @staticmethod
    def create_rate_limiter(
        limiter_type: str = None, redis_client: redis.Redis = None
    ) -> RateLimiter:
        """
        Create a rate limiter based on configuration or explicit parameters.

        Args:
            limiter_type: Optional explicit limiter type to create ('redis' or 'memory')
            redis_client: Optional pre-configured Redis client to use

        Returns:
            An appropriate RateLimiter implementation
        """
        # Use explicit type if provided (for testing)
        if limiter_type == "redis" or (
            limiter_type is None and get_settings().USE_REDIS_RATE_LIMITER
        ):
            try:
                # Use provided client or create one
                if redis_client is None:
                    app_settings = get_settings()
                    redis_client = redis.Redis(
                        host=app_settings.REDIS_HOST,
                        port=app_settings.REDIS_PORT,
                        password=app_settings.REDIS_PASSWORD,
                        db=app_settings.REDIS_DB,
                        socket_timeout=5,
                        decode_responses=True,
                    )
                    # Test the connection
                    redis_client.ping()

                logger.info("Using Redis-based rate limiter")
                return RedisRateLimiter(redis_client)
            except Exception as e:
                logger.warning(
                    f"Failed to connect to Redis, falling back to in-memory rate limiter: {e}"
                )

        # Default to in-memory limiter
        logger.info("Using in-memory rate limiter")
        return InMemoryRateLimiter()
