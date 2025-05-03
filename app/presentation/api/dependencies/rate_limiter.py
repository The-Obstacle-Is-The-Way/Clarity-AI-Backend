"""
Rate limiter dependencies for API routes.

This module implements rate limiting functionality for API endpoints,
following clean architecture principles and ensuring proper security.
Rate limiting is a key component for API security and reliability.
"""

import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.interfaces.services.analytics_service_interface import AnalyticsServiceInterface
from app.infrastructure.di.container import get_container


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
        self._state: Dict[str, Dict[str, Union[int, float]]] = {}
    
    def get_state(self, key: str) -> Dict[str, Union[int, float]]:
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
    
    def increment(self, key: str, reset_after: int) -> Tuple[int, int]:
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
        config: Union[RateLimitConfig, List[RateLimitConfig]],
        key_func: Optional[Callable[[Request], str]] = None
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
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
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
        credentials: Optional[HTTPAuthorizationCredentials],
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
    RateLimitConfig(rate=100, per=60, scope="ip")  # 100 requests per minute per IP
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
    limiters = {
        "default": default_rate_limiter,
        "strict": strict_rate_limiter,
        "auth": auth_rate_limiter,
    }
    return limiters.get(tier, default_rate_limiter)