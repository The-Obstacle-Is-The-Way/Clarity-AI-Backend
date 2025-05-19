"""
Redis-backed Rate Limiter Service

This module provides a distributed rate limiting service using Redis for the NOVAMIND platform.
It implements configurable rate limiting with burst capacity and supports multiple identifier types.
"""

import logging
import time
from datetime import datetime
from enum import Enum

from fastapi import Request, Response

from app.infrastructure.cache.redis_cache import InMemoryFallback, RedisCache

# Configure logger
logger = logging.getLogger(__name__)


class RateLimitType(str, Enum):
    """Enumeration of rate limit types for different endpoints or actions."""

    DEFAULT = "default"
    LOGIN = "login"
    ANALYTICS = "analytics"
    PATIENT_DATA = "patient_data"
    API_KEY = "api_key"


class RateLimitConfig:
    """Configuration for a specific rate limit type."""

    def __init__(
        self,
        requests_per_period: int,
        period_seconds: int,
        burst_capacity: int = 0,
    ):
        """
        Initialize rate limit configuration.

        Args:
            requests_per_period: Number of requests allowed per period
            period_seconds: Period length in seconds
            burst_capacity: Additional requests allowed for burst (default: 0)
        """
        self.requests_per_period = requests_per_period
        self.period_seconds = period_seconds
        self.burst_capacity = burst_capacity


class DistributedRateLimiter:
    """
    Redis-backed distributed rate limiter with token bucket algorithm.

    This implementation provides:
    - Distributed rate limiting using Redis as a shared store
    - Token bucket algorithm for allowing controlled bursts
    - Configurable limits by request type and identifier
    - Multiple identifier options (IP, user ID, API key)
    - Graceful fallback to permissive mode if Redis is unavailable
    """

    # Default rate limit configurations
    DEFAULT_CONFIGS = {
        RateLimitType.DEFAULT: RateLimitConfig(
            requests_per_period=100,  # 100 requests per minute
            period_seconds=60,
            burst_capacity=10,  # Allow 10 extra requests for bursts
        ),
        RateLimitType.LOGIN: RateLimitConfig(
            requests_per_period=5,  # 5 login attempts per minute
            period_seconds=60,
            burst_capacity=0,  # No bursts for login attempts
        ),
        RateLimitType.ANALYTICS: RateLimitConfig(
            requests_per_period=30,  # 30 analytics requests per minute
            period_seconds=60,
            burst_capacity=5,  # Allow 5 extra analytics requests
        ),
        RateLimitType.PATIENT_DATA: RateLimitConfig(
            requests_per_period=60,  # 60 patient data requests per minute
            period_seconds=60,
            burst_capacity=10,  # Allow 10 extra patient data requests
        ),
        RateLimitType.API_KEY: RateLimitConfig(
            requests_per_period=1000,  # 1000 API requests per minute
            period_seconds=60,
            burst_capacity=100,  # Allow 100 extra API requests
        ),
    }

    def __init__(self, cache_service: RedisCache = None):
        """
        Initialize the rate limiter.

        Args:
            cache_service: Redis cache service. If not provided, a new one is created.
        """
        self.cache = cache_service or RedisCache()
        self.configs = self.DEFAULT_CONFIGS.copy()

    def configure(self, limit_type: RateLimitType, config: RateLimitConfig) -> None:
        """
        Update configuration for a specific rate limit type.

        Args:
            limit_type: Type of rate limit to configure
            config: Rate limit configuration
        """
        self.configs[limit_type] = config

    async def is_rate_limited(
        self,
        identifier: str,
        limit_type: RateLimitType = RateLimitType.DEFAULT,
        user_id: str | None = None,
    ) -> tuple[bool, dict[str, int | float | str]]:
        """
        Check if a request should be rate limited.

        Args:
            identifier: Primary identifier (usually IP address)
            limit_type: Type of rate limit to apply
            user_id: Optional user ID for more granular limiting

        Returns:
            Tuple[bool, Dict]: (is_limited, rate_limit_info)
                - is_limited: True if request should be limited
                - rate_limit_info: Information about rate limit status
        """
        # Check if the cache client has been initialized
        # Use the private attribute _client which is set by RedisCache.initialize()
        if not hasattr(self.cache, "_client") or not self.cache._client:
            # Attempt to initialize if not already done (or if fallback occurred)
            await self.cache.initialize()

            # Check again after attempting initialization
            if (
                not hasattr(self.cache, "_client")
                or not self.cache._client
                or isinstance(self.cache._client, InMemoryFallback)
            ):
                # If still no client or it's the fallback, log warning and don't rate limit
                logger.warning(
                    "Cache service unavailable or using in-memory fallback for rate limiting, allowing request"
                )
                return False, {
                    "allowed": True,
                    "reason": "Cache unavailable or in-memory fallback",
                }

        # Get the appropriate configuration
        config = self.configs.get(limit_type, self.configs[RateLimitType.DEFAULT])

        # Create a key that includes both identifier and limit type
        # If user_id is provided, include it for more granular limiting
        rate_limit_key = f"rate_limit:{limit_type}:{identifier}"
        if user_id:
            rate_limit_key = f"{rate_limit_key}:{user_id}"

        now = time.time()
        window_start_time = int(now / config.period_seconds) * config.period_seconds

        # Implement token bucket algorithm
        try:
            # Check if we have a bucket for this key
            exists = await self.cache.exists(rate_limit_key)

            if not exists:
                # Create a new bucket with max tokens minus 1 (for current request)
                total_tokens = config.requests_per_period + config.burst_capacity
                remaining = total_tokens - 1

                # Store bucket information
                await self.cache.set(
                    key=rate_limit_key,
                    value={
                        "remaining": remaining,
                        "reset_at": window_start_time + config.period_seconds,
                        "last_request": now,
                    },
                    expiration=config.period_seconds
                    * 2,  # Use expiration instead of ttl
                )

                # Not rate limited
                rate_limit_info = {
                    "remaining": remaining,
                    "limit": total_tokens,
                    "reset_at": window_start_time + config.period_seconds,
                }
                return False, rate_limit_info

            # Get current bucket information
            bucket = await self.cache.get(rate_limit_key)
            if not bucket:
                # Bucket exists but is empty (race condition or expired)
                # Create a new one
                total_tokens = config.requests_per_period + config.burst_capacity
                remaining = total_tokens - 1

                await self.cache.set(
                    key=rate_limit_key,
                    value={
                        "remaining": remaining,
                        "reset_at": window_start_time + config.period_seconds,
                        "last_request": now,
                    },
                    expiration=config.period_seconds * 2,
                )

                rate_limit_info = {
                    "remaining": remaining,
                    "limit": total_tokens,
                    "reset_at": window_start_time + config.period_seconds,
                }
                return False, rate_limit_info

            # Check if window has reset
            if now >= bucket["reset_at"]:
                # Reset the bucket
                total_tokens = config.requests_per_period + config.burst_capacity
                remaining = total_tokens - 1

                await self.cache.set(
                    key=rate_limit_key,
                    value={
                        "remaining": remaining,
                        "reset_at": window_start_time + config.period_seconds,
                        "last_request": now,
                    },
                    expiration=config.period_seconds * 2,
                )

                rate_limit_info = {
                    "remaining": remaining,
                    "limit": total_tokens,
                    "reset_at": window_start_time + config.period_seconds,
                }
                return False, rate_limit_info

            # Check if we have tokens left
            remaining = bucket["remaining"]
            if remaining <= 0:
                # No tokens left, rate limited
                rate_limit_info = {
                    "remaining": 0,
                    "limit": config.requests_per_period + config.burst_capacity,
                    "reset_at": bucket["reset_at"],
                    "retry_after": max(1, int(bucket["reset_at"] - now)),
                }

                # Log rate limiting event
                logger.warning(
                    f"Rate limit exceeded for {identifier} "
                    f"(type: {limit_type.value}, user_id: {user_id})"
                )

                return True, rate_limit_info

            # We have tokens, decrement and continue
            remaining -= 1

            # Update the bucket
            await self.cache.set(
                key=rate_limit_key,
                value={
                    "remaining": remaining,
                    "reset_at": bucket["reset_at"],
                    "last_request": now,
                },
                expiration=config.period_seconds * 2,
            )

            # Not rate limited
            rate_limit_info = {
                "remaining": remaining,
                "limit": config.requests_per_period + config.burst_capacity,
                "reset_at": bucket["reset_at"],
            }
            return False, rate_limit_info

        except Exception as e:
            # If something goes wrong, log and don't rate limit
            logger.error(f"Error in rate limiter: {e!s}")
            return False, {"allowed": True, "reason": f"Error: {e!s}"}

    async def apply_rate_limit_headers(
        self, response: Response, rate_limit_info: dict[str, int | float | str]
    ) -> None:
        """
        Apply rate limit headers to the response.

        Args:
            response: FastAPI response object
            rate_limit_info: Rate limit information from is_rate_limited
        """
        # Add standard rate limit headers
        response.headers["X-RateLimit-Limit"] = str(rate_limit_info.get("limit", 0))
        response.headers["X-RateLimit-Remaining"] = str(
            rate_limit_info.get("remaining", 0)
        )

        # Add reset header if available
        if "reset_at" in rate_limit_info:
            reset_time = datetime.fromtimestamp(rate_limit_info["reset_at"])
            response.headers["X-RateLimit-Reset"] = reset_time.isoformat()

        # Add retry-after header if rate limited
        if "retry_after" in rate_limit_info:
            response.headers["Retry-After"] = str(rate_limit_info["retry_after"])

    async def process_request(
        self,
        request: Request,
        limit_type: RateLimitType = RateLimitType.DEFAULT,
        user_id: str | None = None,
    ) -> tuple[bool, dict[str, int | float | str]]:
        """
        Process a request for rate limiting.

        Args:
            request: FastAPI request object
            limit_type: Type of rate limit to apply
            user_id: Optional user ID for more granular limiting

        Returns:
            Tuple[bool, Dict]: (is_limited, rate_limit_info)
        """
        # Get client IP address
        client_ip = str(request.client.host) if request.client else "unknown"

        # Check for API key in headers
        api_key = request.headers.get("X-API-Key")

        # Determine identifier based on available information
        if api_key:
            # If API key is present, use it as identifier and API_KEY limit type
            identifier = f"api_key:{api_key}"
            limit_type = RateLimitType.API_KEY
        else:
            # Otherwise use client IP
            identifier = f"ip:{client_ip}"

        # Check if rate limited
        return await self.is_rate_limited(identifier, limit_type, user_id)


# Optional: Clean up expired entries periodically if needed
# pass

# Optional: Default instance for convenience, if not using DI extensively
# Consider using dependency injection (e.g., FastAPI Depends) to manage the instance.
# rate_limiter = DistributedRateLimiter() # COMMENTED OUT: Avoid module-level instantiation

# Singleton instance holder
_default_rate_limiter: DistributedRateLimiter | None = None


def get_rate_limiter() -> DistributedRateLimiter:
    """
    Dependency provider function for getting the rate limiter instance.
    Uses a simple singleton pattern to avoid module-level instantiation issues.

    Returns:
        DistributedRateLimiter: Initialized rate limiter instance.
    """
    global _default_rate_limiter
    if _default_rate_limiter is None:
        logger.info("Creating default DistributedRateLimiter instance.")
        # Instantiation here will correctly load settings via __init__
        _default_rate_limiter = DistributedRateLimiter()
    return _default_rate_limiter
