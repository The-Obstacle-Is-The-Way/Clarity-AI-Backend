"""
Repository dependency providers for the Presentation Layer.

This module centralizes the creation and provision of repository instances
required by API endpoints and other presentation components. It utilizes
factory functions from the infrastructure layer to obtain concrete repository
implementations while depending on repository interfaces defined in the core layer.
"""

import logging
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.infrastructure.database.session import get_async_session
# Import the repository class implementation from the infrastructure layer
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
    SQLAlchemyUserRepository,
)

logger = logging.getLogger(__name__) 


def get_user_repository(
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> IUserRepository:
    """Dependency provider for the User Repository."""
    logger.debug("Providing User Repository dependency")
    # Instantiate the repository with the session
    return SQLAlchemyUserRepository(session)


# Type hint for dependency injection
UserRepoDep = Annotated[IUserRepository, Depends(get_user_repository)]


__all__ = [
    "get_user_repository",
    "UserRepoDep",
]
