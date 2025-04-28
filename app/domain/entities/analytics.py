"""
Analytics Domain Entities.

This module defines the core domain entities related to analytics
within the Novamind Digital Twin platform.
"""

from dataclasses import dataclass
from datetime import datetime
from app.domain.utils.datetime_utils import UTC
from typing import Any, Dict, List, Optional


class AnalyticsEvent:
    """
    Represents a single analytics event captured from user interactions.
    
    This entity encapsulates all the information about a specific event
    that occurred in the system, such as page views, feature usage, or
    critical actions.
    """
    
    def __init__(
        self,
        event_type: str,
        event_data: dict[str, Any],
        user_id: str | None = None,
        session_id: str | None = None,
        timestamp: datetime | None = None,
        event_id: str | None = None
    ) -> None:
        """
        Initialize an analytics event.
        
        Args:
            event_type: Category/type of the event
            event_data: Payload containing event details
            user_id: ID of the user who triggered the event (if available)
            session_id: ID of the session in which the event occurred
            timestamp: When the event occurred (defaults to now if not provided)
            event_id: Unique identifier for the event (typically assigned on storage)
        """
        self.event_type = event_type
        self.event_data = event_data
        self.user_id = user_id
        self.session_id = session_id
        self.timestamp = timestamp or datetime.now(UTC)
        self.event_id = event_id
    
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert the event to a dictionary representation.
        
        Returns:
            Dictionary representation of the event
        """
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'event_data': self.event_data,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

    # -----------------------------------------------------------------
    # Compatibility aliases (used by legacy tests expecting `data` attr)
    # -----------------------------------------------------------------
    @property
    def data(self) -> dict[str, Any]:
        """Alias for :pyattr:`event_data` (test‑suite convenience)."""
        return self.event_data

    @data.setter
    def data(self, value: dict[str, Any]) -> None:  # noqa: D401 – simple alias mutator
        self.event_data = value


class AnalyticsBatch:
    """
    Represents a batch of analytics events processed together.
    
    This entity is used for grouping multiple events for efficient
    processing, storage, or aggregation.
    """
    
    def __init__(
        self,
        events: list[AnalyticsEvent],
        batch_id: str | None = None,
        processed_count: int = 0,
        failed_count: int = 0,
        timestamp: datetime | None = None
    ) -> None:
        """
        Initialize an analytics batch.
        
        Args:
            events: List of analytics events in this batch
            batch_id: Unique identifier for the batch (optional)
            processed_count: Number of successfully processed events
            failed_count: Number of events that failed to process
            timestamp: When the batch was processed
        """
        self.events = events
        self.batch_id = batch_id
        self.processed_count = processed_count
        self.failed_count = failed_count
        self.timestamp = timestamp or datetime.now(UTC)
    
    @property
    def total_count(self) -> int:
        """
        Get the total number of events in the batch.
        
        Returns:
            Total event count (processed + failed)
        """
        return self.processed_count + self.failed_count
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert the batch to a dictionary representation.
        
        Returns:
            Dictionary representation of the batch
        """
        return {
            'batch_id': self.batch_id,
            'events': [event.to_dict() for event in self.events],
            'processed_count': self.processed_count,
            'failed_count': self.failed_count,
            'total_count': self.total_count,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class AnalyticsAggregate:
    """
    Represents aggregated analytics data for reporting and dashboards.
    
    This entity contains the results of analytical queries, typically
    grouped by dimensions such as event type, time period, or user role.
    """
    
    def __init__(
        self,
        dimensions: dict[str, Any],
        metrics: dict[str, Any],
        time_period: dict[str, datetime] | None = None
    ) -> None:
        """
        Initialize an analytics aggregate.
        
        Args:
            dimensions: Dimensions used for grouping the data
            metrics: Calculated metrics based on the grouped data
            time_period: Optional time range for the aggregation
        """
        self.dimensions = dimensions
        self.metrics = metrics
        self.time_period = time_period or {}
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert the aggregate to a dictionary representation.
        
        Returns:
            Dictionary representation of the aggregate
        """
        result = {
            'dimensions': self.dimensions,
            'metrics': self.metrics
        }
        
        # Add time period if available
        if self.time_period:
            formatted_time_period = {}
            for key, value in self.time_period.items():
                if isinstance(value, datetime):
                    formatted_time_period[key] = value.isoformat()
                else:
                    formatted_time_period[key] = value
            
            result['time_period'] = formatted_time_period
            
        return result