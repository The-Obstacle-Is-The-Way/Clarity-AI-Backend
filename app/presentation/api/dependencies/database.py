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

from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
from app.infrastructure.database.session import get_async_session
from app.infrastructure.di.provider import get_repository_instance

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings # Corrected import
from app.infrastructure.persistence.sqlalchemy.config.database import Database, get_db_instance

import logging
logger = logging.getLogger(__name__)

# Generic type for repository interfaces
T = TypeVar('T', bound=BaseRepositoryInterface)

# Type alias for session dependency
DatabaseSessionDep = Annotated[AsyncSession, Depends(get_async_session)]

async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting a database session.
    
    Yields:
        AsyncSession: SQLAlchemy async session.
    """
    logger.debug(f"GET_DB_SESSION: Entered. ID of request.app: {id(request.app)}")
    if hasattr(request.app, 'state'):
        logger.debug(f"GET_DB_SESSION: request.app.state exists. Attributes: {dir(request.app.state)}")
        if hasattr(request.app.state, 'db_session_factory'):
            logger.debug(f"GET_DB_SESSION: db_session_factory FOUND in request.app.state. Type: {type(request.app.state.db_session_factory)}")
        else:
            logger.error("GET_DB_SESSION: db_session_factory NOT FOUND in request.app.state")
    else:
        logger.error("GET_DB_SESSION: request.app has NO 'state' attribute.")

    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is None:
        logger.error("GET_DB_SESSION: Critical - session_factory is None after getattr. Raising RuntimeError.")
        raise RuntimeError(
            "Database session factory not found or invalid on app.state. "
            "Ensure it's initialized during startup."
        )

    async for session in get_async_session(request=request):
        yield session


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
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import PatientRepository as SQLAlchemyPatientRepository

async def get_patient_repository_dependency(
    session: AsyncSession = Depends(get_async_session),
) -> IPatientRepository:
    """Provides an instance of IPatientRepository (SQLAlchemyPatientRepository)."""
    return SQLAlchemyPatientRepository(db_session=session)