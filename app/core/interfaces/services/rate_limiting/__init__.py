"""
Rate Limiting Interface Package.

This package defines the interfaces for rate limiting services
following Clean Architecture principles.
"""

from app.core.interfaces.services.rate_limiting.rate_limiter_interface import (
    IRateLimiter,
    RateLimitConfig,
    RateLimitScope
)

__all__ = [
    "IRateLimiter",
    "RateLimitConfig",
    "RateLimitScope"
]