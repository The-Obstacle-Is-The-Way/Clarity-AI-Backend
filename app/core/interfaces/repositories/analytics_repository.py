"""Interface definition for Analytics Repository."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID


class IAnalyticsRepository(ABC):
    """Repository interface for analytics data."""
    
    @abstractmethod
    async def store_event(self, event_data: dict[str, Any]) -> UUID:
        """Store an analytics event."""
        pass
    
    @abstractmethod
    async def batch_store_events(self, events: list[dict[str, Any]]) -> list[UUID]:
        """Store multiple analytics events in batch."""
        pass
    
    @abstractmethod
    async def get_event(self, event_id: UUID) -> dict[str, Any] | None:
        """Retrieve an analytics event by ID."""
        pass
    
    @abstractmethod
    async def query_events(self, 
                         start_time: datetime | None = None,
                         end_time: datetime | None = None,
                         event_type: str | None = None,
                         user_id: UUID | None = None,
                         limit: int = 100,
                         offset: int = 0) -> list[dict[str, Any]]:
        """Query analytics events with filters."""
        pass
    
    @abstractmethod
    async def get_aggregated_data(self, 
                                dimension: str,
                                metrics: list[str],
                                filters: dict[str, Any] | None = None,
                                start_time: datetime | None = None,
                                end_time: datetime | None = None) -> list[dict[str, Any]]:
        """Get aggregated analytics data."""
        pass