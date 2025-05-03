"""
Rate limiting middleware compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.middleware.rate_limiting_middleware module.

DO NOT USE THIS IN NEW CODE - use app.core.security.rate_limiting instead.
"""

# Re-export from the new location
from app.core.security.rate_limiting import RateLimitingMiddleware

# Re-export RateLimitConfig from the API dependencies
from app.presentation.api.dependencies.rate_limiter import RateLimitConfig, RateLimitScope


def create_rate_limiting_middleware(config: RateLimitConfig):
    """
    Create a rate limiting middleware instance with the specified configuration.
    
    This function maintains backward compatibility with existing code.
    For new code, use RateLimitingMiddleware directly from app.core.security.rate_limiting.
    
    Args:
        config: Rate limit configuration
        
    Returns:
        Rate limiting middleware instance
    """
    return RateLimitingMiddleware(config)