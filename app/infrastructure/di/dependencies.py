"""
Dependency Injection Dependencies.

This module provides functions to access dependency injection
facilities for the application, following SOLID principles.
"""

import logging
from functools import lru_cache

from app.application.services.temporal_neurotransmitter_service import (
    TemporalNeurotransmitterService,
)
from app.domain.entities.neurotransmitter_mapping import (
    create_default_neurotransmitter_mapping,
)
from app.domain.repositories.temporal_repository import (
    EventRepository,
    TemporalSequenceRepository,
)
from app.domain.services.visualization_preprocessor import (
    NeurotransmitterVisualizationPreprocessor,
)
from app.infrastructure.persistence.sqlalchemy.repositories.event_repository import (
    SqlAlchemyEventRepository,
)
from app.infrastructure.persistence.sqlalchemy.repositories.temporal_sequence_repository import (
    SqlAlchemyTemporalSequenceRepository,
)
from app.infrastructure.persistence.sqlalchemy.session import get_db_session

logger = logging.getLogger(__name__)


@lru_cache
def get_service_factory():
    """
    Get a factory for creating service instances.

    Returns:
        Factory function for creating service instances
    """
    return ServiceFactory()


class ServiceFactory:
    """Factory for creating service instances with proper dependencies."""

    async def create_temporal_neurotransmitter_service(
        self,
    ) -> TemporalNeurotransmitterService:
        """
        Create a TemporalNeurotransmitterService instance with proper dependencies.

        Returns:
            Initialized service instance
        """
        logger.debug("Creating TemporalNeurotransmitterService")

        # Create repository instances
        event_repo = await self._create_event_repository()
        sequence_repo = await self._create_temporal_sequence_repository()

        # Create visualization preprocessor
        neurotransmitter_mapping = create_default_neurotransmitter_mapping()
        preprocessor = NeurotransmitterVisualizationPreprocessor(neurotransmitter_mapping)

        # Create and return service instance
        return TemporalNeurotransmitterService(
            event_repository=event_repo,
            sequence_repository=sequence_repo,
            visualization_preprocessor=preprocessor,
        )

    async def _create_event_repository(self) -> EventRepository:
        """
        Create an EventRepository implementation.

        Returns:
            EventRepository instance
        """
        logger.debug("Creating EventRepository")

        # Get database session
        session = None
        async for sess in get_db_session():
            session = sess
            break

        # Create repository with session
        return SqlAlchemyEventRepository(session)

    async def _create_temporal_sequence_repository(self) -> TemporalSequenceRepository:
        """
        Create a TemporalSequenceRepository implementation.

        Returns:
            TemporalSequenceRepository instance
        """
        logger.debug("Creating TemporalSequenceRepository")

        # Get database session
        session = None
        async for sess in get_db_session():
            session = sess
            break

        # Create repository with session
        return SqlAlchemyTemporalSequenceRepository(session)
