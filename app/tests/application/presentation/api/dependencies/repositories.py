"""
Repository Dependencies for FastAPI.

This module provides dependency functions for injecting repository instances
into FastAPI endpoints, following the Dependency Injection pattern.
"""

from fastapi import Depends

from app.application.interfaces.repositories.analytics_repository import AnalyticsRepository
from app.infrastructure.persistence.repositories.analytics_repository import (
    SQLAlchemyAnalyticsRepository,
)
from app.presentation.api.dependencies.database import get_db_session


async def get_analytics_repository(
    db_session = Depends(get_db_session)
) -> AnalyticsRepository:
    """
    Provide an instance of the AnalyticsRepository.
    
    Args:
        db_session: An active database session
        
    Returns:
        An instance of the AnalyticsRepository implementation
    """
    return SQLAlchemyAnalyticsRepository(session=db_session)