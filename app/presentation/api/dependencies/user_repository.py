# -*- coding: utf-8 -*-
"""
User Repository Provider for FastAPI.

This module provides a clean dependency interface for the UserRepository,
ensuring proper handling of database connections and avoiding response model issues.
"""

from fastapi import Depends

from app.domain.repositories.user_repository import UserRepository
from app.infrastructure.repositories.user_repository import SqlAlchemyUserRepository
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_session
from app.core.utils.logging import get_logger

logger = get_logger(__name__)

async def get_user_repository_provider(
    db_session = Depends(get_db_session)
) -> UserRepository:
    """
    Provide a configured UserRepository instance with database session.
    
    This function properly handles dependencies without exposing them directly 
    in a way that would confuse FastAPI's response model generation.
    
    Args:
        db_session: Database session (intentionally not type-annotated)
        
    Returns:
        UserRepository implementation
    """
    # Create and return user repository
    return SqlAlchemyUserRepository(session=db_session) 