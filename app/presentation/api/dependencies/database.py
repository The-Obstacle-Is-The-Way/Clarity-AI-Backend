# -*- coding: utf-8 -*-
"""
Database Dependencies for FastAPI.

This module provides dependency functions for database sessions
to be injected into FastAPI endpoints.
"""

from typing import Generator, AsyncGenerator, Type, TypeVar, Callable # Ensure AsyncGenerator, Type, TypeVar, Callable are imported

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

# Corrected import: Use get_db_session from the config module
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_session as get_session_from_config
from app.config.settings import get_settings
settings = get_settings()

from typing import Optional, Dict, Any # Ensure Optional is imported
from app.core.utils.logging import get_logger
# Remove get_db_instance import if unused, or ensure it exists
# from app.infrastructure.persistence.sqlalchemy.config.database import get_db_instance 

# Import BaseRepository or similar if needed for type hinting
# from app.infrastructure.persistence.sqlalchemy.repositories.base import BaseRepository

logger = get_logger(__name__)

# Define a TypeVar for repository types
T = TypeVar('T')

# Placeholder for repository mapping (replace with DI container logic)
# This maps interface types to concrete implementation classes
_repository_map = {}

# Function to register repository implementations (call this during app setup)
def register_repository(interface: Type[T], implementation: Type[T]):
    global _repository_map
    logger.debug(f"Registering repository: {interface.__name__} -> {implementation.__name__}")
    _repository_map[interface] = implementation

async def get_db() -> AsyncGenerator[AsyncSession, None]: # Correct type hint
    """
    Provide an async database session for endpoints.
    Yields an AsyncSession from the configured session factory.
    """
    async for session in get_session_from_config():
        try:
            yield session
        except Exception as e:
             # Log rollback error if needed, but ensure session handling continues
             logger.error(f"Exception during DB session yield: {e}", exc_info=True)
             # The context manager should handle rollback/close
             raise # Re-raise the exception for FastAPI to handle
        # Session closing/rollback is handled by the context manager in get_session_from_config

def get_repository(repo_type: Type[T]) -> Callable[[AsyncSession], T]: # Return a factory function
    """
    FastAPI dependency factory to get a repository instance.

    This function returns *another function* (a closure) that FastAPI
    will call with the database session dependency.

    Args:
        repo_type: The interface type of the repository to get.

    Returns:
        A function that takes an AsyncSession and returns an instance
        of the requested repository type.
    """
    def _get_repo_instance(session: AsyncSession = Depends(get_db)) -> T:
        # Use the placeholder map (replace with container.resolve)
        implementation = _repository_map.get(repo_type)
        if not implementation:
             logger.error(f"No repository implementation registered for interface {repo_type.__name__}")
             raise NotImplementedError(f"Repository for {repo_type.__name__} not implemented or registered")
        
        logger.debug(f"Providing instance of {implementation.__name__} for interface {repo_type.__name__}")
        # Instantiate the repository with the session
        return implementation(session) 

    return _get_repo_instance