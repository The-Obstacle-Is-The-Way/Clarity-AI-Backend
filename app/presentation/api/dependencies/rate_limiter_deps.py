"""
Rate Limiting FastAPI Dependencies.

This module provides FastAPI-compatible dependencies for rate limiting.
It follows Clean Architecture patterns by depending only on abstractions
and properly injecting concrete implementations.
"""

import logging
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status

from app.core.interfaces.services.rate_limiting.rate_limiter_interface import (
    IRateLimiter,
    RateLimitConfig,
)
from app.infrastructure.security.rate_limiting.providers import get_rate_limiter

# Configure logger
logger = logging.getLogger(__name__)


class RateLimitDependency:
    """
    FastAPI dependency for rate limiting requests.

    This class implements a configurable rate limiter that can
    be applied to API endpoints using FastAPI's dependency injection system.
    It properly follows dependency inversion by depending on the IRateLimiter
    interface rather than concrete implementations.
    """

    def __init__(
        self,
        *,
        requests: int = 10,
        window_seconds: int = 60,
        block_seconds: int = 300,
        scope_key: str = "default",
        error_message: str = "Rate limit exceeded. Please try again later.",
        limiter: Optional[IRateLimiter] = None,
        key_func: Optional[Callable[[Request], str]] = None,
    ):
        """
        Initialize rate limiter dependency.

        Args:
            requests: Maximum number of requests allowed in window
            window_seconds: Time window in seconds
            block_seconds: How long to block when limit exceeded
            scope_key: Scope identifier for this rate limit
            error_message: Custom error message for rate limit errors
            limiter: Rate limiter implementation
            key_func: Function to extract client identifier from request
        """
        self.requests = requests
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self.scope_key = scope_key
        self.error_message = error_message
        self.limiter = limiter
        self.key_func = key_func or self._default_key_func

    async def __call__(self, request: Request) -> None:
        """
        Apply rate limiting to an incoming request.

        Args:
            request: FastAPI request object

        Raises:
            HTTPException: If rate limit exceeded

        Returns:
            None if rate limit not exceeded
        """
        # Lazy-load limiter if not provided in constructor
        if self.limiter is None:
            self.limiter = get_rate_limiter()

        # Get client identifier
        key = await self._get_rate_limit_key(request)

        # Create rate limit config
        config = RateLimitConfig(
            requests=self.requests,
            window_seconds=self.window_seconds,
            block_seconds=self.block_seconds,
            scope_key=self.scope_key,
        )

        # Check and increment rate limit
        try:
            count, reset_seconds = await self.limiter.track_request(key, config)

            # Check if over limit
            if count > self.requests:
                # Log rate limit event
                logger.warning(
                    f"Rate limit exceeded: {key} ({count}/{self.requests}) at {request.url.path}"
                )

                # Add Retry-After header per RFC
                headers = {"Retry-After": str(reset_seconds)}

                # Return error response
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"{self.error_message} Retry after {reset_seconds} seconds.",
                    headers=headers,
                )
        except Exception as e:
            if isinstance(e, HTTPException):
                raise

            # Log error but allow request to proceed
            logger.error(f"Rate limiting error: {str(e)}")

    async def _get_rate_limit_key(self, request: Request) -> str:
        """
        Generate a unique key for rate limiting.

        Args:
            request: FastAPI request

        Returns:
            Unique identifier string
        """
        # Get client identifier
        client_id = self.key_func(request)

        # Create scoped key
        return f"{self.scope_key}:{client_id}"

    def _default_key_func(self, request: Request) -> str:
        """
        Default function to extract client identifier from request.

        Args:
            request: FastAPI request

        Returns:
            Client identifier (usually IP address)
        """
        # Try to get real IP from X-Forwarded-For
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # First address is the client, the rest are proxies
            return forwarded_for.split(",")[0].strip()

        # Fallback to direct client
        if request.client:
            return request.client.host

        # If all else fails
        return "unknown"


# Factory functions for common rate limit configurations


def rate_limit(
    *,
    requests: int = 10,
    window_seconds: int = 60,
    block_seconds: int = 300,
    scope_key: str = "default",
    error_message: str = "Rate limit exceeded. Please try again later.",
) -> RateLimitDependency:
    """
    Standard rate limiter for API endpoints.

    Args:
        requests: Maximum requests in time window
        window_seconds: Time window in seconds
        block_seconds: Block duration when limit exceeded
        scope_key: Scope identifier for this rate limit
        error_message: Custom error message

    Returns:
        Rate limiter dependency
    """
    return RateLimitDependency(
        requests=requests,
        window_seconds=window_seconds,
        block_seconds=block_seconds,
        scope_key=scope_key,
        error_message=error_message,
    )


def sensitive_rate_limit(
    *,
    requests: int = 5,
    window_seconds: int = 60,
    block_seconds: int = 600,
    scope_key: str = "sensitive",
    error_message: str = "Rate limit exceeded for sensitive operation. Please try again later.",
) -> RateLimitDependency:
    """
    Stricter rate limiter for PHI-containing endpoints.

    This applies stricter rate limits for endpoints that handle Protected Health Information,
    helping to enforce HIPAA security requirements and prevent data exfiltration attempts.

    Args:
        requests: Maximum requests in time window
        window_seconds: Time window in seconds
        block_seconds: Block duration when limit exceeded
        scope_key: Scope identifier for this rate limit
        error_message: Custom error message

    Returns:
        Rate limiter dependency with stricter limits
    """
    return RateLimitDependency(
        requests=requests,
        window_seconds=window_seconds,
        block_seconds=block_seconds,
        scope_key=scope_key,
        error_message=error_message,
    )


def admin_rate_limit(
    *,
    requests: int = 100,
    window_seconds: int = 60,
    block_seconds: int = 300,
    scope_key: str = "admin",
    error_message: str = "Admin rate limit exceeded. Please try again later.",
) -> RateLimitDependency:
    """
    More permissive rate limiter for admin endpoints.

    Args:
        requests: Maximum requests in time window
        window_seconds: Time window in seconds
        block_seconds: Block duration when limit exceeded
        scope_key: Scope identifier for this rate limit
        error_message: Custom error message

    Returns:
        Rate limiter dependency with higher limits
    """
    return RateLimitDependency(
        requests=requests,
        window_seconds=window_seconds,
        block_seconds=block_seconds,
        scope_key=scope_key,
        error_message=error_message,
    )
