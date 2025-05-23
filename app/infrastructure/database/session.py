import logging
from collections.abc import AsyncGenerator, Callable

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

    if not any(
        driver in db_url
        for driver in [
            "postgresql+asyncpg",
            "mysql+aiomysql",
            "sqlite+aiosqlite",
        ]
    ):
        url_display = db_url[: db_url.find("@")] + "@..." if "@" in db_url else db_url
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
        logger.exception(f"Failed to create database engine or session factory: {e}")
        raise


# MODIFIED: This is now a utility, not a direct FastAPI dependency function.
# It no longer takes 'request'.
async def get_async_session_utility(
    session_factory: Callable[[], AsyncSession] | None
) -> AsyncGenerator[AsyncSession, None]:
    """Utility to get an async database session using a provided factory."""
    logger.debug("GET_ASYNC_SESSION_UTILITY: Entered.")

    if session_factory is None:
        logger.error("GET_ASYNC_SESSION_UTILITY: session_factory is None. Cannot create session.")
        raise RuntimeError("GET_ASYNC_SESSION_UTILITY: session_factory is None.")

    logger.debug(f"GET_ASYNC_SESSION_UTILITY: Using provided session_factory: {session_factory}")

    session: AsyncSession | None = None
    try:
        session = session_factory()
        logger.debug(f"GET_ASYNC_SESSION_UTILITY: Session created: {session}")
        yield session
    except SQLAlchemyError as e:
        logger.error(f"GET_ASYNC_SESSION_UTILITY: SQLAlchemyError: {e}", exc_info=True)
        if session:
            await session.rollback()
        raise
    except Exception as e:
        logger.error(f"GET_ASYNC_SESSION_UTILITY: Unexpected error: {e}", exc_info=True)
        if session:
            await session.rollback()
        raise
    finally:
        if session:
            try:
                await session.close()
                logger.debug("GET_ASYNC_SESSION_UTILITY: Session closed successfully.")
            except SQLAlchemyError as e:
                logger.error(
                    f"GET_ASYNC_SESSION_UTILITY: SQLAlchemyError during close: {e}",
                    exc_info=True,
                )
            except Exception as e:
                logger.error(
                    f"GET_ASYNC_SESSION_UTILITY: Unexpected error during close: {e}",
                    exc_info=True,
                )


# Test function to simulate dependency usage (not part of actual app logic)
async def example_dependency_using_session(db: AsyncSession) -> None:
    logger.info(f"Example dependency received session: {db}")
    # Use db session here
    pass


# Example of how a router might use it (for illustration)
# from fastapi import APIRouter, Depends
# router = APIRouter()
# @router.get("/test-db")
# async def test_db_endpoint(
#     # This part would be tricky, as get_async_session now needs factory.
#     # The actual dependency in routes would be get_db_session from presentation layer
# ):
#     return {"message": "DB session would be used here"}
