from collections.abc import AsyncGenerator
import logging

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, AsyncEngine
from sqlalchemy.orm import sessionmaker
from fastapi import Request

logger = logging.getLogger(__name__)

def create_db_engine_and_session(db_url: str, echo: bool = False) -> tuple[AsyncEngine, sessionmaker[AsyncSession]]:
    """
    Creates the SQLAlchemy async engine and sessionmaker.

    Args:
        db_url: The database connection URL.
        echo: Whether to enable SQLAlchemy echo logging.

    Returns:
        A tuple containing the created AsyncEngine and sessionmaker.
        
    Raises:
        ValueError: If the db_url is not for a known async driver.
    """
    logger.info(f"Creating DB engine and session for URL: {db_url}")
    if not db_url.startswith(("sqlite+aiosqlite", "postgresql+asyncpg")):
        error_msg = f"Database URL is not configured for a known async driver: {db_url}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    engine = create_async_engine(
        db_url,
        echo=echo,
        future=True,
        pool_pre_ping=True,
    )

    session_local = sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    logger.info("DB Engine and session_local created successfully.")
    return engine, session_local

async def get_async_session(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency function to get an async database session.

    Retrieves the session factory (`sessionmaker` instance) stored in
    `request.app.state.db_session_factory` during application startup.

    Args:
        request: The FastAPI Request object.

    Yields:
        AsyncSession: An active SQLAlchemy async session.
        
    Raises:
        AttributeError: If `request.app.state.db_session_factory` is not set.
        Exception: Re-raises exceptions during session operations after rollback.
    """
    session_factory = getattr(request.app.state, 'db_session_factory', None)
    if not session_factory or not isinstance(session_factory, sessionmaker):
        logger.error("Database session factory 'db_session_factory' not found in app.state or is not a sessionmaker.")
        raise AttributeError("Database session factory not configured in application state.")

    async with session_factory() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Rolling back session due to exception: {e}", exc_info=True)
            await session.rollback()
            raise