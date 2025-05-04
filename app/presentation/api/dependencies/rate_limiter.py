"""
Rate limiter dependencies for API routes.

This module implements rate limiting functionality for API endpoints,
following clean architecture principles and ensuring proper security.
Rate limiting is a key component for API security and reliability.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.interfaces.services.analytics_service_interface import AnalyticsServiceInterface
from app.infrastructure.di.container import get_container


class RateLimitScope(str, Enum):
    """Scope for rate limiting rules."""
    GLOBAL = "global"  # Global rate limit across all users
    USER = "user"      # Per-user rate limit
    IP = "ip"          # Per-IP address rate limit
    PATH = "path"      # Per-endpoint path rate limit
    TOKEN = "token"    # Per-token rate limit (for API tokens)


@dataclass
class RateLimitConfig:
    """
    Configuration for a rate limit rule.
    
    Attributes:
        rate: Maximum number of requests
        per: Time period in seconds
        scope: Scope to apply the rate limit (global, user, ip)
        burst_multiplier: Multiplier for burst capacity
    """
    rate: int
    per: int  # seconds
    scope: str = "ip"  # 'global', 'user', 'ip'
    burst_multiplier: float = 1.5


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


class RateLimitState:
    """
    Store for rate limit state.
    
    In a production environment, this would use Redis or another
    distributed cache for state storage across multiple instances.
    """
    
    def __init__(self):
        """Initialize empty rate limit state storage."""
        self._state: dict[str, dict[str, int | float]] = {}
    
    def get_state(self, key: str) -> dict[str, int | float]:
        """
        Get current state for a rate limit key.
        
        Args:
            key: State key
            
        Returns:
            State dictionary with counts and timestamps
        """
        now = time.time()
        if key not in self._state:
            self._state[key] = {"count": 0, "last_reset": now}
        return self._state[key]
    
    def increment(self, key: str, reset_after: int) -> tuple[int, int]:
        """
        Increment the counter for a key and reset if needed.
        
        Args:
            key: State key
            reset_after: Seconds after which to reset the counter
            
        Returns:
            Tuple of (current count, seconds until reset)
        """
        state = self.get_state(key)
        now = time.time()
        
        # Reset if expired
        if now - state["last_reset"] > reset_after:
            state["count"] = 0
            state["last_reset"] = now
        
        # Increment count
        state["count"] += 1
        
        # Calculate seconds until reset
        reset_at = state["last_reset"] + reset_after
        seconds_until_reset = max(0, int(reset_at - now))
        
        return state["count"], seconds_until_reset


# Global state for rate limits
# In production, use Redis or similar distributed cache
rate_limit_state = RateLimitState()


class RateLimitDependency:
    """
    FastAPI dependency for rate limiting requests.
    
    This class implements a configurable rate limiter that can
    be applied to API endpoints as a dependency.
    """
    
    def __init__(
        self,
        config: RateLimitConfig | list[RateLimitConfig],
        key_func: Callable[[Request], str] | None = None
    ):
        """
        Initialize rate limiter with configuration.
        
        Args:
            config: Rate limit configuration or list of configurations
            key_func: Function to generate a key from the request
        """
        # Ensure config is a list
        self.configs = [config] if isinstance(config, RateLimitConfig) else config
        self.key_func = key_func
        self.security = HTTPBearer(auto_error=False)
        
        # Try to get analytics service for logging rate limit events
        try:
            container = get_container()
            self.analytics = container.get(AnalyticsServiceInterface)
        except (ImportError, KeyError):
            self.analytics = None
    
    async def __call__(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(HTTPBearer(auto_error=False))
    ) -> None:
        """
        Apply rate limiting to the request.
        
        Args:
            request: FastAPI request
            credentials: Optional authorization credentials
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        # Check each configured rate limit
        for config in self.configs:
            # Generate key based on scope
            key = self._get_key(request, credentials, config.scope)
            
            # Apply rate limit
            count, seconds_until_reset = rate_limit_state.increment(key, config.per)
            
            # Calculate allowed requests including burst capacity
            limit = config.rate
            burst_limit = int(limit * config.burst_multiplier)
            
            # Check if limit exceeded
            if count > burst_limit:
                # Log rate limit event if analytics available
                if self.analytics:
                    await self.analytics.track_event(
                        "rate_limit_exceeded",
                        {
                            "path": str(request.url.path),
                            "method": request.method,
                            "client_ip": request.client.host,
                            "scope": config.scope,
                            "limit": limit,
                            "burst_limit": burst_limit,
                            "count": count,
                        }
                    )
                
                # Add headers with rate limit info
                headers = {
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(seconds_until_reset),
                    "Retry-After": str(seconds_until_reset)
                }
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Try again in {seconds_until_reset} seconds.",
                    headers=headers
                )
            
            # Add rate limit headers to response
            request.state.rate_limit_headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(max(0, limit - count)),
                "X-RateLimit-Reset": str(seconds_until_reset)
            }
    
    def _get_key(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials | None,
        scope: str
    ) -> str:
        """
        Generate a rate limit key based on scope.
        
        Args:
            request: FastAPI request
            credentials: Authorization credentials
            scope: Scope for the rate limit
            
        Returns:
            Rate limit key string
        """
        # Use custom key function if provided
        if self.key_func:
            return self.key_func(request)
        
        # Generate key based on scope
        if scope == "global":
            return f"rate_limit:global:{request.url.path}"
        
        if scope == "user" and credentials:
            # Extract user ID from token (would use proper JWT decoding in production)
            return f"rate_limit:user:{credentials.credentials}:{request.url.path}"
        
        # Default to IP-based limiting
        return f"rate_limit:ip:{request.client.host}:{request.url.path}"


# Predefined rate limiters for common scenarios
default_rate_limiter = RateLimitDependency(
    RateLimitConfig(rate=100, per=60, scope=RateLimitScope.IP)  # 100 requests per minute per IP
)

strict_rate_limiter = RateLimitDependency(
    RateLimitConfig(rate=30, per=60, scope="ip")  # 30 requests per minute per IP
)

auth_rate_limiter = RateLimitDependency(
    RateLimitConfig(rate=5, per=60, scope="ip")  # 5 requests per minute per IP for auth endpoints
)


# Utility function to get appropriate rate limiter based on endpoint needs
def get_rate_limiter(tier: str = "default") -> RateLimitDependency:
    """
    Get an appropriate rate limiter based on tier.
    
    Args:
        tier: Rate limit tier (default, strict, auth)
        
    Returns:
        Rate limiter dependency
    """
    if tier == "strict":
        return strict_rate_limiter
    elif tier == "auth":
        return auth_rate_limiter
    else:
        return default_rate_limiter


# HIPAA-compliant rate limits
# These rate limits help prevent DoS attacks and ensure system availability
# as required by the HIPAA Security Rule

def admin_rate_limit() -> RateLimitDependency:
    """
    Rate limiter for admin endpoints - more permissive.
    
    Returns:
        Rate limiter configured for admin routes
    """
    return RateLimitDependency(
        RateLimitConfig(
            rate=300,  # 300 requests
            per=60,    # per minute
            scope=RateLimitScope.USER,
            burst_multiplier=2.0
        )
    )


def rate_limit(tier: str = "default") -> RateLimitDependency:
    """
    Standard rate limiter for API endpoints.
    
    Args:
        tier: Rate limit tier (default, strict, auth)
        
    Returns:
        Rate limiter dependency based on tier
    """
    return get_rate_limiter(tier)


def sensitive_rate_limit() -> RateLimitDependency:
    """
    Rate limiter for sensitive operations containing PHI.
    
    This applies stricter rate limits for endpoints that handle Protected Health Information,
    helping to enforce HIPAA security requirements and prevent data exfiltration attempts.
    
    Returns:
        Rate limiter configured for sensitive PHI operations
    """
    return RateLimitDependency(
        RateLimitConfig(
            rate=30,     # 30 requests
            per=60,      # per minute
            scope=RateLimitScope.USER,
            burst_multiplier=1.2  # Lower burst allowance for sensitive endpoints
        )
    )