"""Interface definition for Analytics Repository."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID


class IAnalyticsRepository(ABC):
    """Repository interface for analytics data."""
    
    @abstractmethod
    async def store_event(self, event_data: Dict[str, Any]) -> UUID:
        """Store an analytics event."""
        pass
    
    @abstractmethod
    async def batch_store_events(self, events: List[Dict[str, Any]]) -> List[UUID]:
        """Store multiple analytics events in batch."""
        pass
    
    @abstractmethod
    async def get_event(self, event_id: UUID) -> Optional[Dict[str, Any]]:
        """Retrieve an analytics event by ID."""
        pass
    
    @abstractmethod
    async def query_events(self, 
                         start_time: Optional[datetime] = None,
                         end_time: Optional[datetime] = None,
                         event_type: Optional[str] = None,
                         user_id: Optional[UUID] = None,
                         limit: int = 100,
                         offset: int = 0) -> List[Dict[str, Any]]:
        """Query analytics events with filters."""
        pass
    
    @abstractmethod
    async def get_aggregated_data(self, 
                                dimension: str,
                                metrics: List[str],
                                filters: Optional[Dict[str, Any]] = None,
                                start_time: Optional[datetime] = None,
                                end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get aggregated analytics data."""
        pass