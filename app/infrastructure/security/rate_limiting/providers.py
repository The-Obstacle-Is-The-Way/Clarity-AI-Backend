"""
Rate Limiter Service Providers.

This module provides dependency injection providers for rate limiting services.
It follows Clean Architecture principles by providing concrete implementations
of the IRateLimiter interface.
"""

import logging
from typing import Optional

from app.core.interfaces.services.rate_limiting.rate_limiter_interface import IRateLimiter
from app.infrastructure.security.rate_limiting.in_memory_limiter import InMemoryRateLimiter

# Configure logger
logger = logging.getLogger(__name__)

# Singleton instance for in-memory rate limiter
_in_memory_limiter_instance: Optional[InMemoryRateLimiter] = None


def get_rate_limiter() -> IRateLimiter:
    """
    Get the application rate limiter service implementation.
    
    This function serves as a dependency provider for FastAPI.
    It returns a singleton instance of the rate limiter to ensure
    consistent rate limiting across requests.
    
    In a production environment, you would likely return a Redis-backed
    or other distributed rate limiter implementation.
    
    Returns:
        IRateLimiter: The configured rate limiter implementation
    """
    global _in_memory_limiter_instance
    
    if _in_memory_limiter_instance is None:
        logger.info("Initializing in-memory rate limiter")
        _in_memory_limiter_instance = InMemoryRateLimiter()
    
    return _in_memory_limiter_instance