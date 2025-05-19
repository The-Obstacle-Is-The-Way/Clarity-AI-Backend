"""
Database dependencies for API routes.

This module provides FastAPI dependency functions for database access,
following clean architecture principles with proper dependency injection patterns.
"""

from collections.abc import AsyncGenerator, Callable
from typing import Annotated, TypeVar

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
from app.infrastructure.di.provider import get_repository_instance
from app.core.config.settings import get_settings  # Corrected import

import logging

logger = logging.getLogger(__name__)

# Generic type for repository interfaces
T = TypeVar("T", bound=BaseRepositoryInterface)


# --- New Dependency to get Session Factory from Request State ---
async def get_session_factory_from_request_state(
    request: Request,
) -> async_sessionmaker[AsyncSession]:
    logger.debug(
        "DEPENDENCY:get_session_factory_from_request_state: Attempting to retrieve actual_session_factory from request.state"
    )

    if not hasattr(request, "state"):
        logger.error(
            "DEPENDENCY:get_session_factory_from_request_state: request has NO 'state' attribute!"
        )
        raise RuntimeError(
            "request has no state attribute, cannot get session factory."
        )

    factory = getattr(request.state, "actual_session_factory", None)

    if factory is None:
        logger.error(
            "DEPENDENCY:get_session_factory_from_request_state: 'actual_session_factory' NOT FOUND on request.state."
        )
        # More detailed logging of request.state content
        req_state_content_for_log = "N/A"
        if hasattr(request.state, "_state") and isinstance(request.state._state, dict):
            req_state_content_for_log = {
                k: type(v) for k, v in request.state._state.items()
            }
        elif isinstance(request.state, dict):
            req_state_content_for_log = {k: type(v) for k, v in request.state.items()}
        elif hasattr(request.state, "__dict__"):
            req_state_content_for_log = {
                k: type(v)
                for k, v in request.state.__dict__.items()
                if not k.startswith("_")
            }
        else:
            req_state_content_for_log = dir(request.state)
        logger.error(
            f"DEPENDENCY:get_session_factory_from_request_state: Content of request.state: {req_state_content_for_log}"
        )
        raise RuntimeError("actual_session_factory not found on request.state")

    logger.debug(
        f"DEPENDENCY:get_session_factory_from_request_state: Successfully retrieved actual_session_factory: {type(factory)}"
    )
    return factory


# --- Modified get_async_session_utility ---
async def get_async_session_utility(
    # Now depends on the renamed dependency above
    factory: async_sessionmaker[AsyncSession] = Depends(
        get_session_factory_from_request_state
    ),
) -> AsyncGenerator[AsyncSession, None]:
    """Yields an SQLAlchemy AsyncSession using a factory from application state."""
    logger.debug(
        f"DEPENDENCY:get_async_session_utility: Received factory: {type(factory)}. Creating session."
    )

    # The factory dependency should raise an error if factory is None,
    # but an additional check can be here if desired, though redundant.
    if not factory:
        logger.error(
            "DEPENDENCY:get_async_session_utility: Session factory is None, cannot create session."
        )
        # This state should ideally be prevented by get_session_factory_from_request_state raising an error.
        raise RuntimeError("Session factory not provided to get_async_session_utility")

    try:
        async with factory() as session:
            logger.debug(
                f"DEPENDENCY:get_async_session_utility: Session {id(session)} created. Yielding session."
            )
            yield session
            logger.debug(
                f"DEPENDENCY:get_async_session_utility: Session {id(session)} context exited."
            )
    except SQLAlchemyError as e:
        logger.error(
            f"DEPENDENCY:get_async_session_utility: SQLAlchemy error during session management: {e}",
            exc_info=True,
        )
        # Depending on policy, you might want to rollback or handle specific exceptions.
        # For now, re-raise to ensure visibility of DB issues.
        raise
    except Exception as e:
        logger.error(
            f"DEPENDENCY:get_async_session_utility: Unexpected error during session management: {e}",
            exc_info=True,
        )
        raise  # Re-raise other unexpected errors
    finally:
        logger.debug("DEPENDENCY:get_async_session_utility: Exiting session utility.")


# Type alias for session dependency
DatabaseSessionDep = Annotated[AsyncSession, Depends(get_async_session_utility)]


# --- Original get_db_session - now simplified ---
async def get_db_session(
    session: AsyncSession = Depends(
        get_async_session_utility
    ),  # Simply depends on the utility
) -> AsyncSession:
    """Injects a database session. This is the primary dependency for routes."""
    logger.debug(
        f"DEPENDENCY:get_db_session: Yielding session {id(session)} from get_async_session_utility."
    )
    return session  # The utility already handles the async generator part, so this just returns the yielded session


# Alias for common usage in routes
get_db = get_db_session


def get_repository(repo_type: type[T]) -> Callable[[AsyncSession], T]:
    """
    Factory function that creates a dependency for getting a repository instance.

    This follows the Repository pattern within Clean Architecture, allowing
    repositories to be injected into API routes according to SOLID principles.

    Args:
        repo_type: The interface type of the repository to inject.

    Returns:
        Callable: A dependency function that provides the repository instance.
    """

    async def _get_repo_with_session(
        session: AsyncSession = Depends(get_db),
    ) -> T:  # Depends on the simplified get_db
        """
        Get a repository instance with the provided database session.

        Args:
            session: The active database session.

        Returns:
            An instance of the requested repository type.
        """
        return get_repository_instance(repo_type, session)

    return _get_repo_with_session


# Specific dependency for Patient Repository
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepository,
)
from app.core.interfaces.repositories.patient_repository import IPatientRepository


async def get_patient_repository_dependency(
    session: AsyncSession = Depends(get_db),
) -> IPatientRepository:
    """Provides an instance of IPatientRepository (PatientRepository)."""
    return PatientRepository(db_session=session)
