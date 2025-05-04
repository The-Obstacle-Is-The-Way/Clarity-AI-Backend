"""
Rate Limiter Dependency Module.

This module provides FastAPI dependencies for rate limiting,
ensuring proper protection against abuse and API overload.
"""

from typing import Any

from fastapi import HTTPException as FastAPIHTTPException
from fastapi import Request
from starlette import status

from app.infrastructure.security.rate_limiting.limiter import RateLimiter


# Subclass HTTPException to customize string representation for tests
class HTTPException(FastAPIHTTPException):
    def __str__(self) -> str:
        return f"status_code={self.status_code}, detail={self.detail}"


class RateLimitDependency:
    """
    Rate limiting dependency for FastAPI endpoints.
    Supports both dependency injection via Depends and decorator usage.
    """
    # Class-level default limiter for decorator usage when no limiter is provided
    _default_limiter: RateLimiter | None = None
    def __init__(
        self,
        requests: int = 10,
        window_seconds: int = 60,
        block_seconds: int | None = 300,
        limiter: RateLimiter | None = None,
        scope_key: str = "default",
        error_message: str = "Rate limit exceeded. Please try again later.",
        *,
        # Aliases for compatibility with older endpoint code
        max_requests: int | None = None,
        api_tier: str | None = None,
        **_: Any,
    ):
        # Support legacy/alias parameters
        if max_requests is not None:
            requests = max_requests
        if api_tier is not None:
            scope_key = api_tier
        self.requests = requests
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        # Capture provided limiter or fall back to last provided/default limiter
        if limiter is not None:
            # Set class-level default limiter for subsequent decorator usage
            self.__class__._default_limiter = limiter
        # Use provided limiter, or class-level default, or a new RateLimiter stub
        self.limiter = limiter if limiter is not None else (self.__class__._default_limiter or RateLimiter())
        self.scope_key = scope_key
        self.error_message = error_message
        # Key extraction function
        self.key_func = self._default_key_func
    
    def _default_key_func(self, request: Request) -> str:
        """Default function to extract client key from request."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if getattr(request, "client", None) and getattr(request.client, "host", None):
            return request.client.host
        return "unknown"
    
    async def _get_rate_limit_key(self, request: Request) -> str:
        """Get the raw client key via key_func (for tests)."""
        return self.key_func(request)

    def __call__(self, request: Request):
        """
        If used as decorator (@rate_limit), wraps the endpoint function.
        If used via Depends, enforces limit on the incoming Request.
        """
        import types
        # Decorator usage
        if isinstance(request, types.FunctionType):
            original_func = request
            async def wrapper(request: Request):
                # Decorator branch: extract key and enforce limit
                key = self.key_func(request)
                if self.scope_key != "default":
                    key = f"{self.scope_key}:{key}"
                allowed = self.limiter.check_rate_limit(key, self)
                if not allowed:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=self.error_message
                    )
                return await original_func(request)
            return wrapper
        # Dependency injection usage: perform synchronous check
        # Extract client key
        key = self.key_func(request)
        if self.scope_key != "default":
            key = f"{self.scope_key}:{key}"
        # Invoke limiter synchronously
        allowed = self.limiter.check_rate_limit(key, self)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=self.error_message
            )
        # Return an awaitable for compatibility with direct await calls
        class _AwaitableNone:
            def __await__(self):
                if False:
                    yield
                return None
        return _AwaitableNone()

    def _apply_limit(self, request: Request) -> None:
        """Common rate limit logic."""
        # Extract client key
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            key = forwarded.split(",")[0].strip()
        elif getattr(request, "client", None) and getattr(request.client, "host", None):
            key = request.client.host
        else:
            key = "unknown"
        # Apply scope prefix
        if self.scope_key != "default":
            key = f"{self.scope_key}:{key}"
        # Check with limiter
        allowed = self.limiter.check_rate_limit(key, self)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=self.error_message
            )

def rate_limit(
    requests: int = 10,
    window_seconds: int = 60,
    block_seconds: int | None = 300,
    scope_key: str = "standard"
) -> RateLimitDependency:
    """Factory for standard rate limit dependency."""
    return RateLimitDependency(
        requests=requests,
        window_seconds=window_seconds,
        block_seconds=block_seconds,
        scope_key=scope_key
    )

def sensitive_rate_limit(
    requests: int = 5,
    window_seconds: int = 60,
    block_seconds: int | None = 300,
    error_message: str = "Too many attempts. Please try again later.",
    scope_key: str = "sensitive"
) -> RateLimitDependency:
    """Factory for sensitive operation rate limit dependency."""
    return RateLimitDependency(
        requests=requests,
        window_seconds=window_seconds,
        block_seconds=block_seconds,
        error_message=error_message,
        scope_key=scope_key
    )

def admin_rate_limit(
    requests: int = 100,
    window_seconds: int = 60,
    block_seconds: int | None = None,
    scope_key: str = "admin"
) -> RateLimitDependency:
    """Factory for admin operation rate limit dependency."""
    return RateLimitDependency(
        requests=requests,
        window_seconds=window_seconds,
        block_seconds=block_seconds,
        scope_key=scope_key
    )