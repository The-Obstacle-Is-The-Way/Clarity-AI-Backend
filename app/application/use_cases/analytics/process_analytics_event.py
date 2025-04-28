# -*- coding: utf-8 -*-
"""
Process Analytics Event Use Case.

This module contains the use case for processing individual analytics events
in real-time as they are received from the frontend or other sources.
"""

from datetime import datetime
from app.domain.utils.datetime_utils import UTC
from typing import Dict, Any, Optional

from app.core.utils.logging import get_logger
from app.domain.entities.analytics import AnalyticsEvent
from app.application.interfaces.repositories.analytics_repository import AnalyticsRepository
from app.application.interfaces.services.cache_service import CacheService


class ProcessAnalyticsEventUseCase:
    """
    Process an individual analytics event in real-time.
    
    This use case handles the validation, sanitization, and storage of individual
    analytics events as they occur. It ensures events are properly captured for
    later aggregation and analysis.
    """
    
    def __init__(
        self, 
        analytics_repository: AnalyticsRepository,
        cache_service: CacheService
    ) -> None:
        """
        Initialize the use case with required dependencies.
        
        Args:
            analytics_repository: Repository for storing analytics events
            cache_service: Service for caching frequently accessed analytics data
        """
        self.analytics_repository = analytics_repository
        self.cache_service = cache_service
        self.logger = get_logger(__name__)
    
    async def execute(
        self, 
        event_type: str,
        event_data: Dict[str, Any],
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> AnalyticsEvent:
        """
        Process a single analytics event.
        
        Args:
            event_type: Category/type of the analytics event
            event_data: Payload containing event details
            user_id: ID of the user who triggered the event (if available)
            session_id: ID of the session in which the event occurred
            timestamp: When the event occurred (defaults to now if not provided)
            
        Returns:
            The processed and stored analytics event
        """
        # Set default timestamp if not provided
        if timestamp is None:
            timestamp = datetime.now(UTC)
        
        # Create the analytics event entity
        analytics_event = AnalyticsEvent(
            event_type=event_type,
            event_data=event_data,
            user_id=user_id,
            session_id=session_id,
            timestamp=timestamp
        )
        
        # Log the event processing (without PHI)
        self.logger.info(
            f"Processing analytics event of type: {event_type}",
            {"session_id": session_id}
        )
        
        # Store the event
        saved_event = await self.analytics_repository.save_event(analytics_event)
        
        # Update real-time counters in cache
        await self._update_realtime_counters(saved_event)
        
        return saved_event
    
    async def _update_realtime_counters(self, event: AnalyticsEvent) -> None:
        """
        Update real-time analytics counters in cache.
        
        This method updates various real-time counters that might be used
        for dashboards or monitoring.
        
        Args:
            event: The analytics event that was processed
        """
        # Generate cache key based on event type
        counter_key = f"analytics:counter:{event.event_type}"
        
        # Increment counter for this event type
        await self.cache_service.increment(counter_key)
        
        # For user-specific events, update user-based counters
        if event.user_id:
            user_counter_key = f"analytics:user:{event.user_id}:{event.event_type}"
            await self.cache_service.increment(user_counter_key)