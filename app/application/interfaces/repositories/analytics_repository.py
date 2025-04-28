# -*- coding: utf-8 -*-
"""
Analytics Repository Interface.

This module defines the interface for accessing and manipulating analytics data,
ensuring a proper separation between the application and infrastructure layers.
"""

from typing import Dict, Any, List, Optional, Protocol
from datetime import datetime

from app.domain.entities.analytics import AnalyticsEvent, AnalyticsAggregate


class AnalyticsRepository(Protocol):
    """
    Interface for analytics data access operations.
    
    This protocol defines the contract that any concrete analytics repository
    implementation must fulfill to be compatible with the application layer.
    """
    
    async def save_event(self, event: AnalyticsEvent) -> AnalyticsEvent:
        """
        Save a single analytics event.
        
        Args:
            event: The analytics event to save
            
        Returns:
            The saved event with any generated fields (e.g., ID)
        """
        ...
    
    async def save_events(self, events: List[AnalyticsEvent]) -> List[AnalyticsEvent]:
        """
        Save multiple analytics events in a batch.
        
        Args:
            events: List of analytics events to save
            
        Returns:
            The saved events with any generated fields
        """
        ...
    
    async def get_event(self, event_id: str) -> Optional[AnalyticsEvent]:
        """
        Retrieve a specific analytics event by ID.
        
        Args:
            event_id: Unique identifier of the event to retrieve
            
        Returns:
            The event if found, None otherwise
        """
        ...
    
    async def get_events(
        self,
        filters: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AnalyticsEvent]:
        """
        Retrieve analytics events that match the specified criteria.
        
        Args:
            filters: Optional dictionary of field-value pairs to filter events
            start_time: Optional start of time range for events
            end_time: Optional end of time range for events
            limit: Maximum number of events to return
            offset: Number of events to skip for pagination
            
        Returns:
            List of matching analytics events
        """
        ...
    
    async def get_aggregates(
        self,
        aggregate_type: str,
        dimensions: List[str],
        filters: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[AnalyticsAggregate]:
        """
        Retrieve aggregated analytics data grouped by specified dimensions.
        
        Args:
            aggregate_type: Type of aggregation to perform (count, sum, avg, etc.)
            dimensions: Fields to group by
            filters: Optional filters to apply before aggregation
            start_time: Optional start of time range for data
            end_time: Optional end of time range for data
            
        Returns:
            List of analytics aggregates containing the grouped data
        """
        ...
    
    async def delete_events(
        self,
        event_ids: Optional[List[str]] = None,
        filters: Optional[Dict[str, Any]] = None,
        older_than: Optional[datetime] = None
    ) -> int:
        """
        Delete analytics events matching the specified criteria.
        
        Args:
            event_ids: Optional list of specific event IDs to delete
            filters: Optional dictionary of field-value pairs to match events
            older_than: Optional datetime to delete events older than this time
            
        Returns:
            Number of events deleted
        """
        ...
    
    async def purge_old_events(self, retention_days: int) -> int:
        """
        Purge events older than the specified retention period.
        
        Args:
            retention_days: Number of days to retain events for
            
        Returns:
            Number of events purged
        """
        ...