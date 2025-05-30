"""
Redis Service Dependency Provider

This module provides dependency injection for Redis-related services,
following clean architecture principles by allowing the presentation layer
to depend on abstractions (interfaces) rather than concrete implementations.
"""

from fastapi import Request

from app.core.interfaces.services.redis_service_interface import IRedisService
from app.infrastructure.services.redis.redis_service import RedisService


def get_redis_service(request: Request) -> IRedisService:
    """
    Dependency provider for Redis service.

    Retrieves the Redis client from the application state and wraps it
    in the appropriate service implementation, returning an interface type
    to follow dependency inversion principle.

    Args:
        request: The FastAPI request object containing application state

    Returns:
        An implementation of IRedisService
    """
    redis_client = request.app.state.redis
    return RedisService(redis_client)
