"""
Rate limiting module for API protection.

This module implements rate limiting functionality to protect against
abuse and DoS attacks, ensuring service stability and availability.
"""

from enum import Enum
from typing import Any

# Import the middleware class
from .middleware import RateLimitingMiddleware
from .service import RateLimiterService, get_rate_limiter_service


# Rate limiting strategy enum
class RateLimitStrategy(str, Enum):
    """Defines different rate limiting strategies."""

    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"


# Rate limiter configuration
class RateLimitConfig:
    """Configuration for rate limiting rules."""

    def __init__(
        self,
        rate_limit_per_minute: int = 60,
        strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW,
        scope_key: str = "ip",
        burst_multiplier: float = 1.5,
    ):
        """
        Initialize rate limiter configuration.

        Args:
            rate_limit_per_minute: Maximum requests per minute
            strategy: Rate limiting algorithm to use
            scope_key: Key to scope the rate limit (ip, user_id, etc.)
            burst_multiplier: Multiplier for burst allowance
        """
        self.rate_limit_per_minute = rate_limit_per_minute
        self.strategy = strategy
        self.scope_key = scope_key
        self.burst_multiplier = burst_multiplier


# Export relevant classes
__all__ = [
    "RateLimitStrategy",
    "RateLimitConfig",
    "RateLimiterService",
    "get_rate_limiter_service",
    "RateLimitingMiddleware",
]
