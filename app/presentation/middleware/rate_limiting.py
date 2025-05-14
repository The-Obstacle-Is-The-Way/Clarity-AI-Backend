"""
Rate Limiting Middleware.

This module implements rate limiting middleware for the FastAPI application,
using the Clean Architecture rate limiting components.
"""

import logging
from typing import Callable, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.interfaces.services.rate_limiting import IRateLimiter, RateLimitConfig
from app.infrastructure.security.rate_limiting.providers import get_rate_limiter
from app.core.security.rate_limiting.limiter import RateLimiter

# Configure logger
logger = logging.getLogger(__name__)


class RateLimitExceededError(HTTPException):
    """
    Exception raised when a rate limit is exceeded.
    """
    
    def __init__(self, detail: str = "Rate limit exceeded", retry_after: int = 60):
        """
        Initialize rate limit error with retry information.
        
        Args:
            detail: Error message
            retry_after: Seconds until retry is allowed
        """
        headers = {"Retry-After": str(retry_after)}
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers=headers
        )


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for applying rate limiting to API requests.
    
    Implements configurable rate limiting with path exclusions.
    """

    def __init__(
        self,
        app,
        limiter: RateLimiter,
        exclude_paths: Optional[List[str]] = None,
        *args,
        **kwargs
    ):
        """
        Initialize middleware with rate limiter and exclusion paths.
        
        Args:
            app: The ASGI application
            limiter: Rate limiter implementation
            exclude_paths: List of URL paths to exclude from rate limiting
        """
        super().__init__(app, *args, **kwargs)
        self.limiter = limiter
        self.exclude_paths = exclude_paths or ["/health", "/metrics"]
        logger.info(f"Rate limiting middleware initialized with exclude paths: {self.exclude_paths}")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with rate limiting.
        
        Args:
            request: Incoming request
            call_next: Function to call next middleware
            
        Returns:
            HTTP response
        """
        # Skip rate limiting for excluded paths
        path = request.url.path
        
        # FIXED: Improved path matching for test endpoints
        if any(excluded in path for excluded in self.exclude_paths) or path.startswith("/test-api/"):
            logger.debug(f"Skipping rate limiting for excluded path: {path}")
            try:
                return await call_next(request)
            except Exception as e:
                # Log and re-raise the exception to be handled by the exception handlers
                logger.error(f"Exception in excluded path (rate limiting middleware): {type(e).__name__}: {str(e)}")
                raise
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Check rate limit
        allowed = await self.limiter.is_allowed(client_ip)
        
        if not allowed:
            # Rate limit exceeded
            logger.warning(f"Rate limit exceeded for IP: {client_ip}, path: {path}")
            # Return 429 Too Many Requests
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Please try again later."},
                headers={"Retry-After": "30"}  # Add Retry-After header for 30 seconds
            )
        
        # Allow the request to continue
        try:
            return await call_next(request)
        except Exception as e:
            # Log and re-raise the exception to be handled by the exception handlers
            logger.error(f"Exception in request (rate limiting middleware): {type(e).__name__}: {str(e)}")
            raise