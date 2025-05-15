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

# Import interfaces for type annotations
from app.core.interfaces.repositories.audit_log_repository_interface import IAuditLogRepository

# Import repository implementations
from app.infrastructure.persistence.repositories.audit_log_repository import AuditLogRepository
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
    SQLAlchemyUserRepository,
)

# Import the database dependency - local import after external imports
from .database import get_db

logger = logging.getLogger(__name__) 


def get_user_repository(
    session: AsyncSession = Depends(get_db),
) -> SQLAlchemyUserRepository:  # Return concrete type instead of interface
    """Dependency provider for the User Repository.
    
    Note: We return the concrete implementation type rather than the interface
    to prevent FastAPI from trying to create a response model from the interface.
    """
    logger.debug("Providing User Repository dependency")
    # Instantiate the repository with the session
    return SQLAlchemyUserRepository(db_session=session)  # Ensure consistent kwarg name


# Type hint for dependency injection
# Use concrete implementation type for FastAPI compatibility
# But annotate with the interface for proper type checking
UserRepoDep = Annotated[SQLAlchemyUserRepository, Depends(get_user_repository)]


async def get_audit_log_repository(db: AsyncSession = Depends(get_db)) -> IAuditLogRepository:
    """
    Get the audit log repository for the current request.
    
    Args:
        db: Database session
        
    Returns:
        IAuditLogRepository: The audit log repository
    """
    return AuditLogRepository(db)


AuditLogRepoDep = Annotated[IAuditLogRepository, Depends(get_audit_log_repository)]

__all__ = [
    "AuditLogRepoDep",
    "UserRepoDep",
    "get_audit_log_repository",
    "get_user_repository",
]
