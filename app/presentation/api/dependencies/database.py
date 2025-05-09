"""
Database dependencies for API routes.

This module provides FastAPI dependency functions for database access,
following clean architecture principles with proper dependency injection patterns.
"""

from collections.abc import AsyncGenerator, Callable
from typing import Annotated, TypeVar

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
from app.infrastructure.database.session import get_async_session_utility
from app.infrastructure.di.provider import get_repository_instance

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings # Corrected import
from app.infrastructure.persistence.sqlalchemy.config.database import Database, get_db_instance

import logging
logger = logging.getLogger(__name__)

# Generic type for repository interfaces
T = TypeVar('T', bound=BaseRepositoryInterface)

# Type alias for session dependency
DatabaseSessionDep = Annotated[AsyncSession, Depends(get_async_session_utility)]

async def get_db_session(
    request: Request,  # FastAPI Request object
    # session_factory_from_request_state: Annotated[
    #     async_scoped_session | None,
    #     Depends(lambda req: getattr(req.app.state, "db_session_factory", None))
    # ]
):
    logger.debug("GET_DB_SESSION (FastAPI Dependency): Entered get_db_session")
    logger.debug(f"GET_DB_SESSION (FastAPI Dependency): id(request) is {id(request)}")
    logger.debug(f"GET_DB_SESSION (FastAPI Dependency): id(request.app) is {id(request.app)}")

    session_factory_from_state = None
    if hasattr(request, 'state'):
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): id(request.state) is {id(request.state)}")
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): request.state content: {request.state.__dict__ if hasattr(request.state, '__dict__') else 'N/A or not a full dict'}")
        # Try to log keys if it's dict-like, or dir() otherwise
        if hasattr(request.state, 'keys') and callable(request.state.keys):
            logger.debug(f"GET_DB_SESSION (FastAPI Dependency): request.state keys: {list(request.state.keys())}")
        else:
            logger.debug(f"GET_DB_SESSION (FastAPI Dependency): dir(request.state): {dir(request.state)}")

        session_factory_from_state = getattr(request.state, "db_session_factory", None)
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): Retrieved session_factory from request.state: {session_factory_from_state}")
    else:
        logger.error("GET_DB_SESSION (FastAPI Dependency): request has no 'state' attribute!")

    # Fallback to request.app.state for safety during transition, though request.state is preferred
    if session_factory_from_state is None and hasattr(request.app, 'state'):
        logger.warning("GET_DB_SESSION (FastAPI Dependency): db_session_factory not found in request.state, attempting fallback to request.app.state")
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): id(request.app.state) is {id(request.app.state)}")
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): request.app.state content: {request.app.state.__dict__ if hasattr(request.app.state, '__dict__') else 'N/A'}")
        session_factory_from_state = getattr(request.app.state, "db_session_factory", None)
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): Retrieved session_factory from request.app.state (fallback): {session_factory_from_state}")

    if session_factory_from_state is None:
        logger.error("GET_DB_SESSION (FastAPI Dependency): db_session_factory not found in request.state or request.app.state. Raising RuntimeError.")
        # Log details about request.state and request.app.state before raising
        if hasattr(request, 'state'):
            logger.error(f"GET_DB_SESSION (FastAPI Dependency): Keys in request.state: {list(request.state.keys()) if hasattr(request.state, 'keys') and callable(request.state.keys) else 'N/A or not dict-like'}")
            logger.error(f"GET_DB_SESSION (FastAPI Dependency): Attributes in request.state: {dir(request.state)}")
        else:
            logger.error("GET_DB_SESSION (FastAPI Dependency): request has no state attribute at point of error.")
        
        if hasattr(request.app, 'state'):
            logger.error(f"GET_DB_SESSION (FastAPI Dependency): Keys in request.app.state: {list(request.app.state.keys()) if hasattr(request.app.state, 'keys') and callable(request.app.state.keys) else 'N/A or not dict-like'}")
            logger.error(f"GET_DB_SESSION (FastAPI Dependency): Attributes in request.app.state: {dir(request.app.state)}")
        else:
            logger.error("GET_DB_SESSION (FastAPI Dependency): request.app has no state attribute at point of error.")
        raise RuntimeError("db_session_factory not found in request.state or request.app.state for get_db_session")

    # Call the utility function, passing the factory
    async for session in get_async_session_utility(session_factory_from_state):
        yield session

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
    
    async def _get_repo_with_session(session: AsyncSession) -> T:
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
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import PatientRepository
from app.core.interfaces.repositories.patient_repository import IPatientRepository

async def get_patient_repository_dependency(
    session: AsyncSession = Depends(get_db),
) -> IPatientRepository:
    """Provides an instance of IPatientRepository (PatientRepository)."""
    return PatientRepository(db_session=session)