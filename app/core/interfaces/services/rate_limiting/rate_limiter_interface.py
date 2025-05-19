"""
Rate Limiter Interface Definition.

This module defines the core interface for rate limiting services,
enabling proper dependency inversion following Clean Architecture principles.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional, Tuple, TypeVar

# Type definitions
Request = TypeVar("Request")  # Generic request type


class RateLimitScope(str, Enum):
    """Scope for rate limiting rules."""

    GLOBAL = "global"  # Global rate limit across all users
    USER = "user"  # Per-user rate limit
    IP = "ip"  # Per-IP address rate limit
    PATH = "path"  # Per-endpoint path rate limit
    TOKEN = "token"  # Per-token rate limit (for API tokens)


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit rule."""

    # Maximum number of requests in time window
    requests: int

    # Time window in seconds
    window_seconds: int

    # Optional block time when limit exceeded (seconds)
    block_seconds: int = 300

    # Scope key to categorize the rate limit
    scope_key: str = "default"


class IRateLimiter(ABC):
    """
    Interface for rate limiting service implementations.

    This abstract base class defines the contract that all rate limiter
    implementations must follow, ensuring proper dependency inversion
    according to SOLID principles.
    """

    @abstractmethod
    def check_rate_limit(self, key: str, config: RateLimitConfig) -> bool:
        """
        Check if a request from the specified key is within rate limits.

        Args:
            key: Unique identifier for the client (IP, user ID, etc.)
            config: Rate limit configuration to apply

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        pass

    @abstractmethod
    async def track_request(self, key: str, config: RateLimitConfig) -> Tuple[int, int]:
        """
        Track a request against the rate limit and return current status.

        Args:
            key: Unique identifier for the client
            config: Rate limit configuration to apply

        Returns:
            Tuple of (current count, seconds until reset)
        """
        pass
