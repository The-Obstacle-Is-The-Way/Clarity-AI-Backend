"""
SQLAlchemy database access module.

This module provides functions for accessing the SQLAlchemy database session.
It serves as a bridge between the old-style session management and the new 
unit-of-work pattern, ensuring backward compatibility during the transition.
"""

import logging
from collections.abc import AsyncGenerator

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config.settings import get_settings
from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work_factory import (
    UnitOfWorkFactory,
)

logger = logging.getLogger(__name__)


async def get_session(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """
    Get an async session from the FastAPI app state.

    This function is designed to be used as a FastAPI dependency and maintains
    compatibility with older code that expects this pattern.

    Args:
        request: The FastAPI request

    Yields:
        AsyncSession: An async SQLAlchemy session

    Raises:
        RuntimeError: If the session factory is not available on app state
    """
    if not hasattr(request.app.state, "actual_session_factory"):
        logger.error("Database session factory not found on app.state")
        raise RuntimeError("Database not initialized. Session factory missing from app state.")

    session_factory = request.app.state.actual_session_factory
    session = None

    try:
        session = session_factory()
        yield session
    except SQLAlchemyError as e:
        logger.error(f"Database session error: {e}", exc_info=True)
        if session:
            await session.rollback()
        raise
    finally:
        if session:
            await session.close()


# Legacy-style session for backward compatibility
SessionLocal = get_session


def get_unit_of_work_factory(request: Request) -> UnitOfWorkFactory:
    """
    Get the unit of work factory from FastAPI app state.

    Args:
        request: The FastAPI request

    Returns:
        UnitOfWorkFactory: The unit of work factory

    Raises:
        RuntimeError: If the unit of work factory is not available on app state
    """
    if not hasattr(request.app.state, "unit_of_work_factory"):
        # If not explicitly set, create one using the session factory
        if hasattr(request.app.state, "actual_session_factory"):
            logger.info("Creating UnitOfWorkFactory on-demand from session factory")
            request.app.state.unit_of_work_factory = UnitOfWorkFactory(
                request.app.state.actual_session_factory
            )
        else:
            logger.error("Cannot create UnitOfWorkFactory: actual_session_factory not found")
            raise RuntimeError("Database not initialized. Session factory not found.")

    return request.app.state.unit_of_work_factory


async def get_session_from_state() -> AsyncGenerator[AsyncSession, None]:
    """
    Get a session using the current settings.

    This is primarily for use in testing and setup code where a Request
    object may not be available.

    Yields:
        AsyncSession: An async SQLAlchemy session
    """
    from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work import (
        create_session_factory,
    )

    settings = get_settings()
    _, session_factory = create_session_factory(settings.ASYNC_DATABASE_URL)

    session = None
    try:
        session = session_factory()
        yield session
    except SQLAlchemyError as e:
        logger.error(f"Database session error: {e}", exc_info=True)
        if session:
            await session.rollback()
        raise
    finally:
        if session:
            await session.close()
