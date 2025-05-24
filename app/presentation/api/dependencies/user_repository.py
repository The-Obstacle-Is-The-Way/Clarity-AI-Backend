"""
User repository dependency provider.

This module provides the dependency injection for user repositories
used throughout the application for user-related operations.
"""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.infrastructure.repositories.sqla.user_repository import SQLAlchemyUserRepository
from app.presentation.api.dependencies.database import get_db


async def get_user_repository(db_session: AsyncSession = Depends(get_db)) -> IUserRepository:
    """
    Provides a user repository implementation.

    Creates and returns a SQLAlchemy-based user repository for accessing user data.

    Args:
        db_session: Database session injected by FastAPI

    Returns:
        An implementation of the IUserRepository interface
    """
    return SQLAlchemyUserRepository(db_session)


# Type annotation for dependency injection
# Use concrete implementation for FastAPI compatibility while preserving
# clean architecture inside the application
UserRepositoryDep = Annotated[SQLAlchemyUserRepository, Depends(get_user_repository)]
