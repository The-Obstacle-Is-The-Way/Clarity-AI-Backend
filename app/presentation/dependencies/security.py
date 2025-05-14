from fastapi import Depends, HTTPException, status
from app.application.interfaces.services.cache_service import CacheService
from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.infrastructure.security.token.redis_token_blacklist_repository import (
    RedisTokenBlacklistRepository,
)
from app.infrastructure.services.redis_cache_service import RedisCacheService
from app.presentation.dependencies.cache import get_cache_service
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

_redis_token_blacklist_repository_instance: RedisTokenBlacklistRepository | None = None

async def get_token_blacklist_repository(
    cache_service: CacheService = Depends(get_cache_service)
) -> ITokenBlacklistRepository:
    """
    Dependency provider for Token Blacklist Repository.

    Returns:
        ITokenBlacklistRepository implementation (Redis-based).
    """
    global _redis_token_blacklist_repository_instance

    if _redis_token_blacklist_repository_instance is not None:
        return _redis_token_blacklist_repository_instance

    if not isinstance(cache_service, RedisCacheService):
        logger.error(
            f"Cache service for TokenBlacklistRepository is not a RedisCacheService instance. Got: {type(cache_service)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error: Cache service misconfiguration."
        )

    _redis_token_blacklist_repository_instance = RedisTokenBlacklistRepository(
        redis_service=cache_service
    )
    return _redis_token_blacklist_repository_instance
