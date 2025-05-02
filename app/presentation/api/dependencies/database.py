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

def get_repository(repo_type: Type[T]) -> Callable[[AsyncSession], T]:
    """
    Dependency factory for obtaining repository instances.
    Returns a function that expects an AsyncSession and returns the repository instance.
    The lookup of the implementation is deferred until the dependency is actually called.
    """
    # This inner function will be returned and called by FastAPI's dependency injection
    def _get_repo_instance_deferred_lookup(session: AsyncSession = Depends(get_db)) -> T:
        # Lookup happens here, when the dependency is resolved for a request
        def _lookup_implementation() -> Type[T]:
            implementation = _repository_map.get(repo_type)
            if implementation is None:
                logger.error(f"Failed to find repository implementation for {repo_type.__name__}")
                # Log current map state for debugging
                logger.debug(f"Current repository map: {_repository_map}")
                raise NotImplementedError(
                    f"No repository implementation registered for {repo_type.__name__}"
                )
            return implementation

        implementation = _lookup_implementation()
        try:
            # Instantiate the concrete repository, passing the session
            instance = implementation(session=session)
            logger.debug(f"Successfully instantiated repository {implementation.__name__} for {repo_type.__name__}")
            return instance
        except Exception as e:
            logger.error(f"Error instantiating repository {implementation.__name__}: {e}", exc_info=True)
            raise  # Re-raise the exception after logging

    # Return the inner function which performs the deferred lookup and instantiation
    return _get_repo_instance_deferred_lookup