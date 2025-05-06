"""
Database dependencies for API routes.

This module provides FastAPI dependency functions for database access,
following clean architecture principles with proper dependency injection patterns.
"""

from collections.abc import AsyncGenerator, Callable
from typing import Annotated, TypeVar

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
from app.infrastructure.database.session import get_async_session
from app.infrastructure.di.provider import get_repository_instance

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