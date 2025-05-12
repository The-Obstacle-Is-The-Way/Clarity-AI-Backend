"""
SQLAlchemy session management module.

This module provides session handling functions to manage database connectivity
in a clean and consistent way following SOLID principles.
"""

import logging
from typing import AsyncGenerator, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.persistence.sqlalchemy.config.database import get_db_session as _get_db_session

logger = logging.getLogger(__name__)

# Re-export for backward compatibility
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that yields a SQLAlchemy async session.
    
    This function is used as a FastAPI dependency to provide a database
    session to route handlers. It ensures proper session lifecycle management.
    
    Yields:
        AsyncSession: SQLAlchemy async session for DB operations
    """
    logger.debug("Using get_db from sqlalchemy.session")
    async for session in _get_db_session():
        yield session 