import logging
from collections.abc import AsyncGenerator

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)


def create_db_engine_and_session(
    db_url: str, echo: bool = False
) -> tuple[AsyncEngine, sessionmaker[AsyncSession]]:
    """Create the SQLAlchemy async engine and session factory.

    Args:
        db_url: The database connection URL.
        echo: Whether to enable SQL echoing.

    Returns:
        A tuple containing the async engine and the session factory.

    Raises:
        ValueError: If the database URL is not suitable for an async driver.
    """
    logger.info("Creating database engine and session factory.")

    # Basic validation for async driver in URL
    if not any(
        driver in db_url
        for driver in [
            "postgresql+asyncpg",
            "mysql+aiomysql",
            "sqlite+aiosqlite",
        ]
    ):
        # Shorten the f-string part for display
        url_display = db_url[: db_url.find('@')] + "@..." if '@' in db_url else db_url
        error_msg = f"Database URL '{url_display}' does not seem to use a supported async driver."
        logger.error(error_msg)
        raise ValueError(error_msg)

    try:
        engine = create_async_engine(db_url, echo=echo, pool_pre_ping=True)
        session_local = sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
        logger.info("Database engine and session factory created successfully.")
        return engine, session_local
    except SQLAlchemyError as e:
        logger.exception(
            f"Failed to create database engine or session factory: {e}"
        )
        raise  # Re-raise the exception after logging


async def get_async_session(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency to get an async database session.

    Uses the session factory stored in the application state.

    Args:
        request: The incoming FastAPI request.

    Yields:
        An AsyncSession instance.

    Raises:
        RuntimeError: If the session factory is not found in app state.
        SQLAlchemyError: If there is an error during session handling.
    """
    session_factory = getattr(request.app.state, "db_session_factory", None)
    
    logger.debug(f"get_async_session: id(request.app): {id(request.app)}, id(request.app.state): {id(request.app.state)}") # DEBUG
    logger.debug(f"get_async_session: request.app.state contents: {vars(request.app.state) if hasattr(request.app.state, '__dict__') else request.app.state}") # DEBUG
    logger.debug(f"get_async_session: session_factory from state: {session_factory} (type: {type(session_factory)})") # DEBUG

    if session_factory is None or not callable(session_factory):
        error_msg = "Database session factory not found or invalid in application state."
        logger.critical(
            "Critical error: 'db_session_factory' missing or invalid in app.state. "
            "Check application lifespan initialization."
        )
        raise RuntimeError(error_msg)

    session: AsyncSession | None = None
    try:
        async with session_factory() as session:
            logger.debug("Database session opened.")
            yield session
            logger.debug("Database session yielded.")
    except SQLAlchemyError as e:
        logger.exception(f"Database session error: {e}")
        if session:
            await session.rollback()
            logger.warning("Session rolled back due to SQLAlchemyError.")
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during database session: {e}")
        if session:
            await session.rollback()
            logger.error("Session rolled back due to unexpected error.")
        raise
    finally:
        logger.debug("Database session context exited.")