"""
SQLAlchemy session management module.

This module provides session handling functions to manage database connectivity
in a clean and consistent way following SOLID principles.
"""

import logging
from typing import AsyncGenerator, Callable

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

from app.core.config.settings import get_settings
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_session as _get_db_session

logger = logging.getLogger(__name__)

# Create the base class for models
Base = declarative_base()

# Re-export for backward compatibility
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that yields a SQLAlchemy async session.
    
    This function is used as a FastAPI dependency to provide a database
    session to route handlers. It ensures proper session lifecycle management.
    
    Yields:
        AsyncSession: SQLAlchemy async session for DB operations
    """
    logger.debug("Using get_db from sqlalchemy.session")
    async for session in _get_db_session():
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
        future=True
    )
    
    session_factory = async_sessionmaker(
        engine,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
        class_=AsyncSession
    )
    
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close() 