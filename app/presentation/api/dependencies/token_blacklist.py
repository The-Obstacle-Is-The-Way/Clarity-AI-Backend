"""
Token blacklist repository dependency provider.

This module provides the dependency injection for token blacklist repositories
used in the token revocation and session management flows, following
Clean Architecture principles.
"""

from typing import Annotated

from fastapi import Depends

from app.core.config.settings import get_settings
from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.infrastructure.security.token.redis_token_blacklist_repository import (
    RedisTokenBlacklistRepository,
)
from app.infrastructure.services.redis.redis_cache_service import RedisCacheService


async def get_token_blacklist_repository() -> ITokenBlacklistRepository:
    """
    Provides a token blacklist repository implementation following Clean Architecture.
    
    Returns a Redis-based implementation for production use that implements
    the ITokenBlacklistRepository interface from the core layer.
    
    Returns:
        An implementation of ITokenBlacklistRepository interface
    """
    # Get application settings for Redis configuration
    settings = get_settings()
    
    # Parse Redis URL to get host and port
    # Expected format: redis://hostname:port/db
    redis_url = settings.REDIS_URL
    redis_parts = redis_url.replace("redis://", "").split("/")[0].split(":")
    redis_host = redis_parts[0] or "localhost"
    redis_port = int(redis_parts[1]) if len(redis_parts) > 1 else 6379
    
    # Create Redis service with proper configuration
    redis_service = RedisCacheService(
        host=redis_host,
        port=redis_port,
        ssl=settings.REDIS_SSL,
        prefix="novamind:token:"
    )
    
    # Return the repository implementation that depends on the interface
    return RedisTokenBlacklistRepository(redis_service=redis_service)


# Type annotation for dependency injection
# Use interface type for clean architecture while still allowing FastAPI dependency injection
TokenBlacklistRepositoryDep = Annotated[
    ITokenBlacklistRepository, Depends(get_token_blacklist_repository)
]
