"""
SQLAlchemy session management module.

This module provides session handling functions to manage database connectivity
in a clean and consistent way following SOLID principles.
"""

import logging
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from app.core.config.settings import get_settings

logger = logging.getLogger(__name__)

# Create the base class for models
Base = declarative_base()


# Re-export get_db_session from the database config module
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that yields a SQLAlchemy async session.

    This function is used as a FastAPI dependency to provide a database
    session to route handlers. It ensures proper session lifecycle management.

    Yields:
        AsyncSession: SQLAlchemy async session for DB operations
    """
    logger.debug("Using get_db from sqlalchemy.session")
    async for session in get_db_session():
        yield session


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get a database session for use in services and repositories.

    This function provides a database session that can be used in application
    services and repositories. It ensures proper session lifecycle management.

    Yields:
        AsyncSession: SQLAlchemy async session for DB operations
    """
    logger.debug("Getting database session for repository or service")

    settings = get_settings()
    engine = create_async_engine(
        settings.ASYNC_DATABASE_URL,
        echo=settings.ENVIRONMENT == "development",
        future=True,
    )

    session_factory = async_sessionmaker(
        engine,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
        class_=AsyncSession,
    )

    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


# Export the get_db_session function directly
__all__ = ["Base", "get_db", "get_db_session"]
