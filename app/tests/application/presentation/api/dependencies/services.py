"""
PAT service dependency for FastAPI.

This module exposes a named DI provider so that unit tests may override
the PAT service via FastAPI's dependency_overrides.
"""

import logging

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.interfaces.services.cache_service import CacheService
from app.application.services.digital_twin_service import DigitalTwinApplicationService
from app.core.dependencies.database import get_db_session
from app.core.services.ml.pat import (
    InitializationError,
    PATInterface,
    PATServiceFactory,
)
from app.infrastructure.cache.redis_cache import RedisCache
from app.infrastructure.persistence.repositories.digital_twin_repository import (
    DigitalTwinRepository,
)

logger = logging.getLogger(__name__)


async def get_pat_service() -> PATInterface:
    """Return a configured PAT service instance, or 503 if initialization fails."""
    try:
        factory = PATServiceFactory()
        # defaulting to mock; override via settings if needed
        service = factory.create_service("mock")
        # minimal config for mock/demo
        service.initialize({"mock_delay_ms": 100})
        return service
    except InitializationError as e:
        logger.error(f"Failed to initialize PAT service: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PAT service is currently unavailable",
        )


async def get_digital_twin_service(
    session: AsyncSession = Depends(get_db_session),
) -> DigitalTwinApplicationService:
    """Provide a fully‑wired ``DigitalTwinApplicationService`` instance.

    The repository is constructed with the request‑scoped SQLAlchemy
    session, keeping the dependency side‑effect free at import‑time and
    allowing easy override within the unit‑test suite.
    """

    repository = DigitalTwinRepository(session)
    return DigitalTwinApplicationService(repository)


async def get_cache_service() -> CacheService:
    """Return a lazily‑connected Redis‑backed cache service instance.

    The Redis client initialises itself on first use so we simply return
    the object.  Tests can override this dependency with an in‑memory
    stub if required via FastAPI's ``dependency_overrides``.
    """

    return RedisCache()
