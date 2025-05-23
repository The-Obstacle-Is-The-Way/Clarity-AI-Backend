"""
User repository dependency provider.

This module provides the dependency injection for user repositories
used throughout the application for user-related operations.
"""

from typing import Annotated

from fastapi import Depends

from app.infrastructure.repositories.sqla.user_repository import SQLAlchemyUserRepository
from app.presentation.api.dependencies.db_session import get_db_session


def get_user_repository():
    """
    Provides a user repository implementation.

    Creates and returns a SQLAlchemy-based user repository for accessing user data.

    Returns:
        An implementation of the IUserRepository interface
    """
    db_session = next(get_db_session())
    return SQLAlchemyUserRepository(db_session)


# Type annotation for dependency injection
# Use concrete implementation for FastAPI compatibility while preserving
# clean architecture inside the application
UserRepositoryDep = Annotated[SQLAlchemyUserRepository, Depends(get_user_repository)]
