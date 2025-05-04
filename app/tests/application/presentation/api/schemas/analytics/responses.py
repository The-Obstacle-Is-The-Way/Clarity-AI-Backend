"""
Analytics API response schemas.

This module defines the Pydantic schemas for formatting responses from
the analytics endpoints in the Novamind Digital Twin platform.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AnalyticsEventResponse(BaseModel):
    """
    Schema for response when a single analytics event is processed.
    
    This model defines the response format when tracking a user interaction
    or system event through the analytics API.
    """
    
    event_id: str = Field(
        ...,
        description="Unique identifier for the processed event",
        examples=["evt-1234-abcd-5678-efgh"]
    )
    
    event_type: str = Field(
        ...,
        description="Category or type of the analytics event",
        examples=["page_view", "feature_usage", "session_start"]
    )
    
    event_data: dict[str, Any] = Field(
        ...,
        description="Sanitized payload containing details about the event",
        examples=[{"page": "/dashboard", "time_on_page": 45}]
    )
    
    user_id: str | None = Field(
        None,
        description="Identifier of the user who triggered the event (if available)",
        examples=["provider-123", "admin-456"]
    )
    
    session_id: str | None = Field(
        None,
        description="Identifier of the session in which the event occurred",
        examples=["session-789-xyz"]
    )
    
    timestamp: datetime = Field(
        ...,
        description="When the event occurred",
        examples=["2025-03-30T12:00:00Z"]
    )
    
    processed_at: datetime = Field(
        ...,
        description="When the event was processed by the system",
        examples=["2025-03-30T12:00:01Z"]
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "event_id": "evt-1234-abcd-5678-efgh",
            "event_type": "page_view",
            "event_data": {"page": "/dashboard", "time_on_page": 45},
            "user_id": "provider-123",
            "session_id": "session-789-xyz",
            "timestamp": "2025-03-30T12:00:00Z",
            "processed_at": "2025-03-30T12:00:01Z"
        }
    })


class AnalyticsEventsBatchResponse(BaseModel):
    """
    Schema for response when a batch of analytics events is processed.
    
    This model defines the response format for batch processing multiple
    events in a single request, with processing statistics.
    """
    
    batch_id: str | None = Field(
        None,
        description="Identifier for this batch of events (if provided)"
    )
    
    processed_count: int = Field(
        ...,
        description="Number of events successfully processed",
        ge=0
    )
    
    failed_count: int = Field(
        ...,
        description="Number of events that failed to process",
        ge=0
    )
    
    total_count: int = Field(
        ...,
        description="Total number of events in the batch",
        ge=0
    )
    
    events: list[AnalyticsEventResponse] = Field(
        ...,
        description="List of successfully processed events",
        max_items=1000
    )
    
    timestamp: datetime = Field(
        ...,
        description="When the batch was processed"
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "batch_id": "batch-2345-bcde",
            "processed_count": 95,
            "failed_count": 5,
            "total_count": 100,
            "events": [
                {
                    "event_id": "evt-1234-abcd-5678-efgh",
                    "event_type": "page_view",
                    "event_data": {"page": "/dashboard"},
                    "user_id": "provider-123",
                    "session_id": "session-789-xyz",
                    "timestamp": "2025-03-30T12:00:00Z",
                    "processed_at": "2025-03-30T12:00:01Z"
                }
            ],
            "timestamp": "2025-03-30T12:01:00Z"
        }
    })


class MetricValue(BaseModel):
    """
    Schema for a single metric value in aggregated analytics.
    
    This model represents an individual measurement or calculation
    in an analytics aggregate, with metadata about the value.
    """
    
    value: Any = Field(
        ...,
        description="The calculated metric value",
        examples=[123, 45.7, "category", True]
    )
    
    type: str = Field(
        ...,
        description="Data type of the metric",
        examples=["integer", "float", "string", "boolean", "timestamp"]
    )
    
    format: str | None = Field(
        None,
        description="Formatting hint for display (e.g., 'percentage', 'currency')",
        examples=["percentage", "currency:USD", "duration:seconds", "filesize"]
    )
    
    confidence: float | None = Field(
        None,
        description="Confidence level in the metric (0-1, if applicable)",
        ge=0,
        le=1
    )


class AnalyticsAggregateResponse(BaseModel):
    """
    Schema for a single aggregated analytics result.
    
    This model defines the response format for a single aggregate
    result used in analytics dashboards and reports.
    """
    
    dimensions: dict[str, Any] = Field(
        ...,
        description="Dimensions used for grouping the data",
        examples=[{"event_type": "page_view"}, {"user_role": "provider", "date": "2025-03-30"}]
    )
    
    metrics: dict[str, MetricValue] = Field(
        ...,
        description="Calculated metrics for this aggregate group",
        examples=[{
            "count": {
                "value": 125,
                "type": "integer"
            },
            "avg_duration": {
                "value": 45.3,
                "type": "float",
                "format": "duration:seconds"
            }
        }]
    )
    
    time_period: dict[str, datetime] | None = Field(
        None,
        description="Optional time range for this aggregate"
    )


class AnalyticsAggregatesListResponse(BaseModel):
    """
    Schema for a list of aggregated analytics results.
    
    This model defines the response format for dashboard data
    containing multiple aggregated results.
    """
    
    aggregates: list[AnalyticsAggregateResponse] = Field(
        ...,
        description="List of analytics aggregates"
    )
    
    total_count: int = Field(
        ...,
        description="Total number of aggregates returned",
        ge=0
    )
    
    query_info: dict[str, Any] = Field(
        ...,
        description="Information about the query performed",
        examples=[{
            "aggregate_type": "count",
            "dimensions": ["event_type"],
            "time_range": {
                "start": "2025-03-29T00:00:00Z",
                "end": "2025-03-30T00:00:00Z"
            },
            "filters_applied": {"platform": "web"}
        }]
    )
    
    cached: bool = Field(
        False,
        description="Whether this result was served from cache"
    )
    
    generated_at: datetime = Field(
        ...,
        description="When this result was generated"
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "aggregates": [
                {
                    "dimensions": {"event_type": "page_view"},
                    "metrics": {
                        "count": {"value": 125, "type": "integer"},
                        "avg_duration": {"value": 45.3, "type": "float", "format": "duration:seconds"}
                    }
                },
                {
                    "dimensions": {"event_type": "feature_usage"},
                    "metrics": {
                        "count": {"value": 80, "type": "integer"}
                    }
                }
            ],
            "total_count": 2,
            "query_info": {
                "aggregate_type": "count",
                "dimensions": ["event_type"],
                "time_range": {"start": "2025-03-29T00:00:00Z", "end": "2025-03-30T00:00:00Z"},
                "filters_applied": {"platform": "web"}
            },
            "cached": False,
            "generated_at": "2025-03-30T12:05:00Z"
        }
    })