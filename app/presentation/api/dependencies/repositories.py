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
# REMOVED: from app.infrastructure.database.session import get_async_session
# ADDED: Import get_db from the local database dependency module
from .database import get_db

# Import the repository class implementation from the infrastructure layer
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
    SQLAlchemyUserRepository,
)

from app.infrastructure.persistence.repositories.audit_log_repository import AuditLogRepository
from app.core.interfaces.repositories.audit_log_repository_interface import IAuditLogRepository

logger = logging.getLogger(__name__) 


def get_user_repository(
    session: Annotated[AsyncSession, Depends(get_db)], # CHANGED to Depends(get_db)
) -> IUserRepository:
    """Dependency provider for the User Repository."""
    logger.debug("Providing User Repository dependency")
    # Instantiate the repository with the session
    return SQLAlchemyUserRepository(db_session=session) # Ensure consistent kwarg name


# Type hint for dependency injection
UserRepoDep = Annotated[IUserRepository, Depends(get_user_repository)]


async def get_audit_log_repository(db: AsyncSession = Depends(get_db)) -> IAuditLogRepository:
    """
    Get the audit log repository for the current request.
    
    Args:
        db: Database session
        
    Returns:
        IAuditLogRepository: The audit log repository
    """
    return AuditLogRepository(db)


__all__ = [
    "get_user_repository",
    "UserRepoDep",
    "get_audit_log_repository",
]
