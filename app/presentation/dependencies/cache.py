from urllib.parse import urlparse

from fastapi import Depends, HTTPException, status

from app.application.interfaces.services.cache_service import CacheService
from app.config.settings import Settings, get_settings
from app.infrastructure.services.redis_cache_service import RedisCacheService
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

_redis_cache_service_instance: RedisCacheService | None = None

async def get_cache_service(
    settings: Settings = Depends(get_settings)
) -> CacheService:
    """
    Dependency provider for the CacheService.

    Initializes and returns a RedisCacheService instance based on application settings.
    Uses a singleton pattern for the RedisCacheService instance.
    """
    global _redis_cache_service_instance

    if _redis_cache_service_instance is not None:
        return _redis_cache_service_instance

    if not settings.REDIS_URL:
        logger.error("REDIS_URL is not configured.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cache service is not configured."
        )

    try:
        parsed_url = urlparse(settings.REDIS_URL)
        host = parsed_url.hostname
        port = parsed_url.port
        password = parsed_url.password
        # Determine SSL based on scheme (rediss implies SSL)
        ssl_enabled = parsed_url.scheme == "rediss"

        if not host or not port:
            logger.error(f"Invalid REDIS_URL format: {settings.REDIS_URL}")
            raise ValueError("Invalid REDIS_URL format, missing host or port.")

        _redis_cache_service_instance = RedisCacheService(
            host=host,
            port=port,
            password=password,
            ssl=ssl_enabled,
            prefix=f"{settings.PROJECT_NAME.lower().replace(' ', '_')}:cache:"
        )
        logger.info(f"RedisCacheService initialized for host: {host}:{port}")
        # It's good practice to test the connection if possible, 
        # but RedisCacheService doesn't have an explicit connect method.
        # Operations will fail later if connection is bad.
        return _redis_cache_service_instance
    except ValueError as ve:
        logger.error(f"ValueError during RedisCacheService initialization: {ve!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Invalid cache configuration: {ve!s}"
        )
    except Exception as e:
        logger.error(f"Failed to initialize RedisCacheService: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not initialize cache service."
        )
