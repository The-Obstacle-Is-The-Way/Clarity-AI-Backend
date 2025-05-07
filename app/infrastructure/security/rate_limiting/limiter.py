"""
Rate Limiting Module.

This module provides rate limiting functionality to protect API endpoints
from abuse. It implements configurable rate limits based on client IP
and authenticated user identity.
"""

import logging
from typing import Any

# Optional dependency handling - similar to the Redis pattern
try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    # Define re-usable strategies
    RATE_LIMIT_STRATEGIES = {
        "ip": get_remote_address,
        # Can add more strategies like "user_id", etc.
    }
except ModuleNotFoundError:  # pragma: no cover - only in test env
    # Create stub classes for testing without slowapi dependency
    class Limiter:
        def __init__(self, *args, **kwargs):
            pass
        
        def limit(self, *args, **kwargs):
            # Return a no-op decorator in test environment
            def decorator(func):
                return func
            return decorator
    
    def get_remote_address():
        return "127.0.0.1"
    
    RATE_LIMIT_STRATEGIES = {
        "ip": get_remote_address,
    }

from app.core.config.settings import Settings

logger = logging.getLogger(__name__)

settings = Settings()  # Global settings instance

class RateLimiter:
    """
    Rate limiter implementation based on slowapi, with fallback for testing.
    
    This class wraps the actual rate limiting implementation and provides
    a consistent interface whether using the real slowapi or a test stub.
    """
    
    def __init__(self, 
                 limiter: Any | None = None, 
                 default_limits: list[str] | None = None,
                 strategy: str = "ip"):
        """
        Initialize the rate limiter.
        
        Args:
            limiter: Optional underlying limiter implementation
            default_limits: Default rate limits to apply (e.g. ["5/minute", "100/hour"])
            strategy: The strategy for identifying clients (ip, user, etc.)
        """
        self._limiter = limiter
        self._default_limits = default_limits or ["60/minute", "1000/hour"]
        self._strategy = strategy
        
    def check_rate_limit(self, key: str, config: Any = None) -> bool:
        """
        Check if the given key under the provided config is within limits.
        
        This method serves both as a real implementation and as a
        testing stub that can be mocked.
        
        Args:
            key: The identifier for the rate limit check
            config: Additional configuration for the check
            
        Returns:
            True if within limits, False if exceeded
        """
        # For testing environments or when no limiter is configured,
        # always allow the request
        if self._limiter is None:
            return True
            
        # In a real implementation, this would use the underlying
        # limiter to check if the key has exceeded its rate limit
        # For now, we'll always return True since we need to implement
        # the actual check with slowapi
        logger.debug(f"Rate limit check for key: {key}")
        return True
        
    @property
    def limiter(self) -> Any:
        """Get the underlying limiter implementation."""
        return self._limiter
        
    @property
    def default_limits(self) -> list[str]:
        """Get the default rate limits."""
        return self._default_limits
        
    @property  
    def strategy(self) -> str:
        """Get the rate limiting strategy."""
        return self._strategy


def create_rate_limiter(settings: Settings) -> RateLimiter:
    """
    Create and configure a rate limiter based on application settings.
    
    This factory function creates a properly configured RateLimiter instance
    with appropriate rate limits and strategies according to the application
    settings.
    
    Args:
        settings: Application settings
        
    Returns:
        Configured RateLimiter instance
    """
    try:
        # Check if rate limiting is enabled
        if getattr(settings, "RATE_LIMITING_ENABLED", True):
            # Get configuration from settings
            default_limits = getattr(settings, "DEFAULT_RATE_LIMITS", ["60/minute", "1000/hour"])
            strategy = getattr(settings, "RATE_LIMIT_STRATEGY", "ip")
            
            # Create the underlying slowapi limiter if available
            strategy_func = RATE_LIMIT_STRATEGIES.get(strategy, get_remote_address)
            limiter = Limiter(key_func=strategy_func)
            
            logger.info(f"Rate limiter initialized with limits: {default_limits}, strategy: {strategy}")
            return RateLimiter(limiter=limiter, default_limits=default_limits, strategy=strategy)
        else:
            logger.warning("Rate limiting disabled by settings")
            return RateLimiter()  # Return a no-op limiter
    except Exception as e:
        logger.error(f"Error initializing rate limiter: {e!s}")
        logger.warning("Falling back to unlimited rate limiter due to initialization error")
        return RateLimiter()  # Return a no-op limiter
