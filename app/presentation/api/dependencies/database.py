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

async def get_db_session(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Injects a database session into the request.
    This is the actual FastAPI dependency.
    It retrieves session_factory from app.state and calls the utility function.
    """
    logger.debug(f"GET_DB_SESSION (FastAPI Dependency): Entered. ID of request.app: {id(request.app)}")
    session_factory_from_state: Callable[[], AsyncSession] | None = None
    
    if hasattr(request.app, 'state'):
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): id(request.app.state) is {id(request.app.state)}")
        # Ensure we log the actual content of the state if it exists
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): request.app.state content: {request.app.state.__dict__ if hasattr(request.app.state, '__dict__') else 'N/A'}")
        session_factory_from_state = getattr(request.app.state, "db_session_factory", None)
        logger.debug(f"GET_DB_SESSION (FastAPI Dependency): Retrieved session_factory: {session_factory_from_state}")
    else:
        logger.warning("GET_DB_SESSION (FastAPI Dependency): request.app has NO state attribute.")

    if session_factory_from_state is None:
        logger.error("GET_DB_SESSION (FastAPI Dependency): db_session_factory not found. Raising RuntimeError.")
        if hasattr(request.app, 'state'):
            logger.error(f"GET_DB_SESSION (FastAPI Dependency): Keys in request.app.state: {list(request.app.state.keys()) if isinstance(request.app.state, dict) else 'N/A (not a dict)'}")
            logger.error(f"GET_DB_SESSION (FastAPI Dependency): Attributes in request.app.state: {dir(request.app.state)}")
        else:
            logger.error("GET_DB_SESSION (FastAPI Dependency): request.app has no state attribute at point of error.")
        raise RuntimeError("db_session_factory not found in request.app.state for get_db_session")

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