# -*- coding: utf-8 -*-
"""
Cache Infrastructure Package.

This package provides implementations of the CacheService interface,
including Redis-based caching for production and in-memory caching for
development and testing.
"""

from app.infrastructure.cache.redis_cache import RedisCache

__all__ = ["RedisCache"]