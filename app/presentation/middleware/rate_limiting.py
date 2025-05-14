"""
Rate Limiting Middleware.

This module implements rate limiting middleware for the FastAPI application,
using the Clean Architecture rate limiting components.
"""

import logging
from typing import Callable, Optional

from fastapi import FastAPI, HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.interfaces.services.rate_limiting import IRateLimiter, RateLimitConfig
from app.infrastructure.security.rate_limiting.providers import get_rate_limiter

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
    Middleware for global rate limiting.
    
    This middleware applies rate limiting at the application level,
    complementing the endpoint-specific rate limiting provided by dependencies.
    It properly follows dependency inversion by depending on IRateLimiter.
    """
    
    def __init__(
        self,
        app: FastAPI,
        *,
        limiter: Optional[IRateLimiter] = None,
        requests_per_minute: int = 60,
        exclude_paths: Optional[list[str]] = None,
        key_func: Optional[Callable[[Request], str]] = None
    ):
        """
        Initialize rate limiting middleware.
        
        Args:
            app: FastAPI application
            limiter: Rate limiter implementation
            requests_per_minute: Request limit per minute
            exclude_paths: Paths to exclude from rate limiting
            key_func: Function to extract client identifier from request
        """
        super().__init__(app)
        self.limiter = limiter or get_rate_limiter()
        self.requests_per_minute = requests_per_minute
        # Always exclude test endpoints to prevent infinite recursion
        default_exclude = ["/health", "/metrics", "/test-api", "/docs", "/redoc", "/openapi.json"]
        self.exclude_paths = (exclude_paths or []) + default_exclude
        self.key_func = key_func or self._default_key_func
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
        if any(excluded in path for excluded in self.exclude_paths):
            logger.debug(f"Skipping rate limiting for excluded path: {path}")
            return await call_next(request)
        
        # Get client identifier
        client_id = self.key_func(request)
        
        # Configure rate limit
        config = RateLimitConfig(
            requests=self.requests_per_minute,
            window_seconds=60,
            scope_key="global"
        )
        
        try:
            # Check and record rate limit
            count, reset_seconds = await self.limiter.track_request(f"global:{client_id}", config)
            
            # Check if over limit
            if count > self.requests_per_minute:
                # Log rate limit event
                logger.warning(
                    f"Global rate limit exceeded: {client_id} ({count}/{self.requests_per_minute}) "
                    f"at {request.url.path}"
                )
                
                # Return rate limit exceeded response directly without raising exception
                return Response(
                    content=f"Rate limit exceeded. Limit: {self.requests_per_minute} per minute. Please try again later.",
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(reset_seconds)}
                )
            
            # Proceed with request if within limits
            return await call_next(request)
        
        except Exception as e:
            # Log error but allow request to proceed in case of rate limiting failure
            logger.error(f"Rate limiting error: {str(e)}")
            print(f"Warning: Using placeholder InMemoryRateLimiter for {client_id}. Allowing request.")
            return await call_next(request)
    
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