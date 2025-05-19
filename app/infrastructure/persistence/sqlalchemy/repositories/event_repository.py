"""
SQL Alchemy implementation of the event repository.

This module provides a SQLAlchemy-based implementation of the
EventRepository interface for temporal event storage and retrieval.
"""

from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.temporal_events import CorrelatedEvent, EventChain
from app.domain.repositories.temporal_repository import EventRepository
from app.infrastructure.persistence.sqlalchemy.models.temporal_sequence_model import EventModel


class SqlAlchemyEventRepository(EventRepository):
    """
    SQLAlchemy implementation of the event repository.
    
    This repository handles the persistence of correlated events, including
    event chains and relationships between events.
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize with a SQLAlchemy session."""
        self.session = session
    
    async def save_event(self, event: CorrelatedEvent) -> UUID:
        """
        Save a single event.
        
        Args:
            event: The event to save
            
        Returns:
            UUID of the saved event
        """
        # Map domain entity to ORM model, including event metadata
        # Use event.event_metadata if present, otherwise fallback to event.metadata
        meta = getattr(event, 'event_metadata', None)
        if meta is None:
            meta = event.metadata
        event_model = EventModel(
            id=event.event_id,
            correlation_id=event.correlation_id,
            parent_event_id=event.parent_event_id,
            patient_id=event.patient_id,
            event_type=event.event_type,
            timestamp=event.timestamp,
            event_metadata=meta
        )
        
        self.session.add(event_model)
        await self.session.flush()
        
        return event.event_id
    
    async def get_event_by_id(self, event_id: UUID) -> CorrelatedEvent | None:
        """
        Get an event by its ID.
        
        Args:
            event_id: UUID of the event
            
        Returns:
            CorrelatedEvent if found, None otherwise
        """
        result = await self.session.execute(
            sa.select(EventModel).where(EventModel.id == event_id)
        )
        event_model = result.scalars().first()
        
        if not event_model:
            return None
        
        return self._model_to_entity(event_model)
    
    async def get_events_by_correlation_id(self, correlation_id: UUID) -> list[CorrelatedEvent]:
        """
        Get all events with the specified correlation ID.
        
        Args:
            correlation_id: The correlation ID to search for
            
        Returns:
            List of correlated events
        """
        result = await self.session.execute(
            sa.select(EventModel)
            .where(EventModel.correlation_id == correlation_id)
            .order_by(EventModel.timestamp)
        )
        event_models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in event_models]
    
    async def get_event_chain(self, correlation_id: UUID) -> EventChain:
        """
        Get a complete event chain by correlation ID.
        
        Args:
            correlation_id: The correlation ID of the chain
            
        Returns:
            EventChain containing all related events
        """
        events = await self.get_events_by_correlation_id(correlation_id)
        return EventChain(events=events)
    
    async def get_patient_events(
        self, 
        patient_id: UUID, 
        event_type: str | None = None,
        limit: int = 100
    ) -> list[CorrelatedEvent]:
        """
        Get events associated with a patient.
        
        Args:
            patient_id: UUID of the patient
            event_type: Optional filter for event type
            limit: Maximum number of events to return
            
        Returns:
            List of events matching the criteria
        """
        query = sa.select(EventModel).where(EventModel.patient_id == patient_id)
        
        if event_type:
            query = query.where(EventModel.event_type == event_type)
        
        query = query.order_by(sa.desc(EventModel.timestamp)).limit(limit)
        
        result = await self.session.execute(query)
        event_models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in event_models]
    
    def _model_to_entity(self, model: EventModel) -> CorrelatedEvent:
        """
        Convert a database model to a domain entity.
        
        Args:
            model: The database model
            
        Returns:
            Domain entity
        """
        # Map ORM model to domain entity
        return CorrelatedEvent(
            event_id=model.id,
            correlation_id=model.correlation_id,
            parent_event_id=model.parent_event_id,
            patient_id=model.patient_id,
            event_type=model.event_type,
            timestamp=model.timestamp,
            metadata=model.event_metadata
        ) 