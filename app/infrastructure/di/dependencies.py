"""
Dependency Injection Dependencies.

This module provides functions to access dependency injection
facilities for the application, following SOLID principles.
"""

import logging
from functools import lru_cache
from typing import Any

from app.application.services.temporal_neurotransmitter_service import TemporalNeurotransmitterService
from app.domain.entities.neurotransmitter_mapping import create_default_neurotransmitter_mapping
from app.domain.repositories.temporal_repository import EventRepository, TemporalSequenceRepository
from app.domain.services.visualization_preprocessor import NeurotransmitterVisualizationPreprocessor
from app.infrastructure.di.provider import get_service_instance
from app.infrastructure.persistence.sqlalchemy.repositories.event_repository import SqlAlchemyEventRepository
from app.infrastructure.persistence.sqlalchemy.repositories.temporal_sequence_repository import SqlAlchemyTemporalSequenceRepository
from app.infrastructure.persistence.sqlalchemy.session import get_db_session

logger = logging.getLogger(__name__)

class ServiceFactory:
    """Factory for creating application services."""
    
    def __init__(self):
        """Initialize the service factory."""
        self._services = {}
    
    async def get_temporal_neurotransmitter_service(self) -> TemporalNeurotransmitterService:
        """
        Get or create a TemporalNeurotransmitterService instance.
        
        Returns:
            An initialized TemporalNeurotransmitterService instance
        """
        # Use a cache key for the service
        cache_key = "temporal_neurotransmitter_service"
        
        # Return cached instance if available
        if cache_key in self._services:
            return self._services[cache_key]
        
        # Create new instance
        # Get a database session
        db_session = await anext(get_db_session())
        
        # Create required repositories
        sequence_repository = SqlAlchemyTemporalSequenceRepository(session=db_session)
        event_repository = SqlAlchemyEventRepository(session=db_session)
        
        # Create visualization preprocessor
        visualization_preprocessor = NeurotransmitterVisualizationPreprocessor()
        
        # Create XGBoost service if available (using dynamic import to avoid circular imports)
        xgboost_service = None
        try:
            from app.core.services.ml.xgboost.factory import get_xgboost_service
            xgboost_service = get_xgboost_service()
        except ImportError:
            logger.warning("XGBoost service not available, continuing without it")
        
        # Create and initialize service
        service = TemporalNeurotransmitterService(
            sequence_repository=sequence_repository,
            event_repository=event_repository,
            visualization_preprocessor=visualization_preprocessor,
            xgboost_service=xgboost_service
        )
        
        # Cache the instance
        self._services[cache_key] = service
        
        return service

@lru_cache(maxsize=1)
def get_service_factory() -> ServiceFactory:
    """
    Get the service factory singleton.
    
    Returns:
        The ServiceFactory instance
    """
    return ServiceFactory() 