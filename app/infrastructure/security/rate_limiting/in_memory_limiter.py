"""
In-Memory Rate Limiter Implementation.

This module provides a simple in-memory implementation of the IRateLimiter
interface. For production use, this would be replaced with a distributed
implementation based on Redis or similar technology.
"""

import time
from typing import Dict, Tuple

from app.core.interfaces.services.rate_limiting.rate_limiter_interface import (
    IRateLimiter, 
    RateLimitConfig
)


class InMemoryRateLimiter(IRateLimiter):
    """
    Simple in-memory implementation of the rate limiter interface.
    
    This implementation stores rate limit counters in memory, making it
    suitable for development, testing, or single-instance deployments.
    For production use with multiple instances, use a distributed implementation.
    """
    
    def __init__(self):
        """Initialize empty rate limit state storage."""
        self._state: Dict[str, Dict[str, int | float]] = {}
    
    def check_rate_limit(self, key: str, config: RateLimitConfig) -> bool:
        """
        Check if a request is within rate limits without incrementing counters.
        
        Args:
            key: Unique identifier for the client (IP, user ID, etc.)
            config: Rate limit configuration to apply
            
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        state = self._get_state(key)
        now = time.time()
        
        # Reset if window expired
        if now - state["last_reset"] > config.window_seconds:
            return True
            
        # Check if under limit
        return state["count"] < config.requests
    
    async def track_request(
        self,
        key: str,
        config: RateLimitConfig
    ) -> Tuple[int, int]:
        """
        Track a request against the rate limit and return current status.
        
        Args:
            key: Unique identifier for the client
            config: Rate limit configuration to apply
            
        Returns:
            Tuple of (current count, seconds until reset)
        """
        state = self._get_state(key)
        now = time.time()
        
        # Reset if window expired
        if now - state["last_reset"] > config.window_seconds:
            state["count"] = 0
            state["last_reset"] = now
        
        # Increment count
        state["count"] += 1
        
        # Calculate seconds until reset
        reset_at = state["last_reset"] + config.window_seconds
        seconds_until_reset = max(0, int(reset_at - now))
        
        return state["count"], seconds_until_reset
    
    def _get_state(self, key: str) -> Dict[str, int | float]:
        """
        Get or initialize state for a key.
        
        Args:
            key: State key
            
        Returns:
            State dictionary with count and timestamps
        """
        now = time.time()
        if key not in self._state:
            self._state[key] = {"count": 0, "last_reset": now}
        return self._state[key]