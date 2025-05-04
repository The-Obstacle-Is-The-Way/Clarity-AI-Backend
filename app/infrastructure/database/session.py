"""
Database session management module.

This module provides SQLAlchemy session management functionality
following clean architecture principles with proper separation of concerns.
"""

from collections.abc import AsyncGenerator
import logging

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

logger = logging.getLogger(__name__)

logger.info(f"Attempting to create async engine with URL: {settings.DATABASE_URL}")

if not settings.DATABASE_URL.startswith("sqlite+aiosqlite") and not settings.DATABASE_URL.startswith("postgresql+asyncpg"):
    error_msg = f"DATABASE_URL is not configured for a known async driver: {settings.DATABASE_URL}"
    logger.error(error_msg)
    raise ValueError(error_msg)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=getattr(settings, 'DB_ECHO_LOG', False),
    future=True,
    pool_pre_ping=True,
)

AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

logger.info("Async database engine and sessionmaker configured successfully.")


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function to get an async database session.

    Yields:
        AsyncSession: Session for async database operations
    """
    logger.debug("Creating async session from AsyncSessionLocal")
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Rolling back session due to exception: {e}")
            await session.rollback()
            raise