"""
Rate Limiter Service Implementation.

This module adapts the core IRateLimiter interface to the RateLimiterService
interface used by the presentation layer middleware.
"""

import logging

from fastapi import Request

from app.core.interfaces.services.rate_limiting.rate_limiter_interface import (
    IRateLimiter,
    RateLimitConfig,
)
from app.core.security.rate_limiting.service import RateLimiterService
from app.infrastructure.security.rate_limiting.in_memory_limiter import InMemoryRateLimiter

# Configure logger
logger = logging.getLogger(__name__)


class RateLimiterServiceImpl(RateLimiterService):
    """
    Implementation of the RateLimiterService interface.

    This adapter connects the presentation layer middleware with the
    core rate limiting components, following Clean Architecture principles.
    """

    def __init__(self, rate_limiter: IRateLimiter | None = None):
        """
        Initialize with a rate limiter implementation.

        Args:
            rate_limiter: The core rate limiter to use, or None to create a default
        """
        self._limiter = rate_limiter or InMemoryRateLimiter()
        self._default_config = RateLimitConfig(
            requests=100,  # 100 requests
            window_seconds=60,  # per minute
        )
        logger.info("RateLimiterServiceImpl initialized")

    async def is_allowed(self, identifier: str) -> bool:
        """
        Check if a request from the given identifier is allowed.

        Args:
            identifier: Unique key identifying the request source

        Returns:
            True if the request is allowed, False otherwise
        """
        return self._limiter.check_rate_limit(identifier, self._default_config)

    async def check_rate_limit(self, request: Request) -> bool:
        """
        Check if the request is within rate limits.

        Args:
            request: The incoming HTTP request

        Returns:
            True if the request is allowed, False if rate limited
        """
        # Extract client IP to use as the rate limit key
        client_ip = request.client.host if request.client else "unknown"

        # Check rate limit using the core rate limiter
        allowed = self._limiter.check_rate_limit(client_ip, self._default_config)

        if not allowed:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")

        return allowed


def get_rate_limiter_service() -> RateLimiterService:
    """
    Factory function to create a RateLimiterService.

    Returns:
        An implementation of RateLimiterService
    """
    return RateLimiterServiceImpl()
