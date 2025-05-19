"""
Stub implementation for Rate Limiting Middleware.

This file provides a placeholder for the RateLimitingMiddleware class,
which is required by other parts of the application but was previously missing.
See Memory 83e40060.
"""

import logging

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Middleware for rate limiting requests."""

    def __init__(
        self,
        app,
        rate_limiter=None,
        limiter=None,
        redis_service=None,
        default_limits=None,
        exclude_paths=None,
        **kwargs,
    ):
        """
        Initialize the rate limiting middleware.

        Args:
            app: The ASGI application
            rate_limiter: The rate limiter service (legacy parameter name)
            limiter: The rate limiter service (new parameter name)
            redis_service: Redis service for rate limiting (legacy parameter)
            default_limits: Default rate limits configuration (used in tests)
            exclude_paths: Paths to exclude from rate limiting
            **kwargs: Additional keyword arguments for backward compatibility
        """
        super().__init__(app)
        # Prior implementations used different parameter names; this handles both
        # to maintain compatibility with existing code and tests
        self.rate_limiter = rate_limiter or limiter
        self.default_limits = default_limits
        self.exclude_paths = exclude_paths or ["/health", "/metrics", "/docs", "/redoc"]

        # For test environments, create a mock rate limiter that always allows requests
        if self.rate_limiter is None:
            logger.info(
                "No rate limiter provided; creating a test limiter that always allows requests"
            )
            from unittest.mock import AsyncMock

            self.rate_limiter = AsyncMock()
            self.rate_limiter.check_rate_limit = AsyncMock(return_value=True)
            self.rate_limiter.is_allowed = AsyncMock(return_value=True)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """
        Process the request and apply rate limiting if configured.

        Args:
            request: The incoming request
            call_next: The next middleware or endpoint handler

        Returns:
            Response: The HTTP response
        """
        # Skip rate limiting for excluded paths
        path = request.url.path
        if any(excluded in path for excluded in self.exclude_paths):
            return await call_next(request)

        if self.rate_limiter:
            # Try both methods to support different implementations
            if hasattr(self.rate_limiter, "check_rate_limit"):
                can_proceed = await self.rate_limiter.check_rate_limit(request)
            elif hasattr(self.rate_limiter, "is_allowed"):
                # Get client IP
                client_ip = request.client.host if request.client else "unknown"
                can_proceed = await self.rate_limiter.is_allowed(client_ip)
            else:
                # Default to allowing the request if neither method exists
                can_proceed = True

            if not can_proceed:
                return Response(
                    content="Rate limit exceeded. Please try again later.",
                    status_code=429,
                    media_type="text/plain",
                )

        # If no rate limiter or allowed by rate limiter, proceed with the request
        return await call_next(request)


# Ensure the class name matches what's expected by importers
__all__ = ["RateLimitingMiddleware"]
