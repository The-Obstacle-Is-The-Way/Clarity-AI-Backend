"""
Stub implementation for Rate Limiting Middleware.

This file provides a placeholder for the RateLimitingMiddleware class,
which is required by other parts of the application but was previously missing.
See Memory 83e40060.
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from .service import RateLimiterService

class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Stub Middleware for rate limiting requests."""

    def __init__(self, app, rate_limiter=None, limiter=None, default_limits=None, **kwargs):
        """
        Initialize the rate limiting middleware.
        
        Args:
            app: The ASGI application
            rate_limiter: The rate limiter service (legacy parameter name)
            limiter: The rate limiter service (new parameter name)
            default_limits: Default rate limits configuration (used in tests)
            **kwargs: Additional keyword arguments for backward compatibility
        """
        super().__init__(app)
        # Prior implementations used different parameter names; this handles both
        # to maintain compatibility with existing code and tests
        self.rate_limiter = rate_limiter or limiter
        self.default_limits = default_limits
        
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """
        Process the request and apply rate limiting if configured.
        
        Args:
            request: The incoming request
            call_next: The next middleware or endpoint handler
            
        Returns:
            Response: The HTTP response
        """
        if self.rate_limiter:
            # Check if the request should be rate limited
            can_proceed = await self.rate_limiter.check_rate_limit(request)
            if not can_proceed:
                return Response(
                    content="Rate limit exceeded. Please try again later.",
                    status_code=429,
                    media_type="text/plain"
                )
        
        # If no rate limiter or allowed by rate limiter, proceed with the request
        return await call_next(request)

# Ensure the class name matches what's expected by importers
__all__ = ["RateLimitingMiddleware"]
