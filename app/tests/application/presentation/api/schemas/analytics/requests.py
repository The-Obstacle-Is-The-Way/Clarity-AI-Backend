"""
Analytics API request schemas.

This module defines the Pydantic schemas for validating incoming requests
to the analytics endpoints in the Novamind Digital Twin platform.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class AnalyticsEventCreateRequest(BaseModel):
    """
    Schema for creating a single analytics event.

    This model validates requests to record individual analytics events like
    page views, feature usage, or other trackable user interactions.
    """

    event_type: str = Field(
        ...,
        description="Category or type of the analytics event",
        examples=["page_view", "feature_usage", "session_start"],
    )

    event_data: dict[str, Any] = Field(
        ...,
        description="Payload containing details about the event",
        examples=[{"page": "/dashboard", "time_on_page": 45}],
    )

    user_id: str | None = Field(
        None,
        description="Identifier of the user who triggered the event (if available)",
        examples=["provider-123", "admin-456"],
    )

    session_id: str | None = Field(
        None,
        description="Identifier of the session in which the event occurred",
        examples=["session-789-xyz"],
    )

    timestamp: datetime | None = Field(
        None,
        description="When the event occurred (defaults to current time if not provided)",
        examples=["2025-03-30T12:00:00Z"],
    )

    @model_validator(mode="after")
    def sanitize_event_data(self) -> "AnalyticsEventCreateRequest":
        """
        Sanitize the event data to ensure no PHI is accidentally included.

        This validator removes any potential PHI fields from event_data.
        """
        # Fields that might contain PHI and should be removed
        phi_fields = [
            "patient_name",
            "patient_id",
            "mrn",
            "dob",
            "ssn",
            "address",
            "email",
            "phone",
            "full_name",
            "name",
            "date_of_birth",
        ]

        if self.event_data:
            for field in phi_fields:
                if field in self.event_data:
                    del self.event_data[field]

        return self


class AnalyticsEventItem(BaseModel):
    """
    Schema for a single event in a batch request.

    This model represents an individual event within a batch processing request.
    """

    event_type: str = Field(..., description="Category or type of the analytics event")

    event_data: dict[str, Any] = Field(
        ..., description="Payload containing details about the event"
    )

    user_id: str | None = Field(
        None,
        description="Identifier of the user who triggered the event (if available)",
    )

    session_id: str | None = Field(
        None, description="Identifier of the session in which the event occurred"
    )

    timestamp: str | None = Field(None, description="When the event occurred, as ISO 8601 string")


class AnalyticsEventsBatchRequest(BaseModel):
    """
    Schema for processing multiple analytics events in a batch.

    This model validates requests to process batches of events, typically
    used for bulk imports or processing accumulated events.
    """

    events: list[AnalyticsEventItem] = Field(
        ...,
        description="List of analytics events to process",
        min_length=1,
        max_length=1000,
    )

    batch_id: str | None = Field(None, description="Optional identifier for this batch of events")

    @model_validator(mode="after")
    def sanitize_events(self) -> "AnalyticsEventsBatchRequest":
        """
        Sanitize all events in the batch to ensure no PHI is included.

        This validator removes potential PHI fields from all events.
        """
        # Fields that might contain PHI and should be removed
        phi_fields = [
            "patient_name",
            "patient_id",
            "mrn",
            "dob",
            "ssn",
            "address",
            "email",
            "phone",
            "full_name",
            "name",
            "date_of_birth",
        ]

        if self.events:
            for event in self.events:
                for field in phi_fields:
                    if field in event.event_data:
                        del event.event_data[field]

        return self


class AnalyticsAggregationRequest(BaseModel):
    """
    Schema for retrieving aggregated analytics data.

    This model validates requests to fetch analytics aggregates for dashboards
    and reporting, with various filtering and grouping options.
    """

    aggregate_type: str = Field(
        ...,
        description="Type of aggregation to perform",
        examples=["count", "sum", "avg", "min", "max"],
    )

    dimensions: list[str] = Field(
        ...,
        description="Dimensions to group data by",
        examples=[["event_type"], ["user_role", "event_type"], ["date"]],
    )

    filters: dict[str, Any] | None = Field(
        None,
        description="Optional filters to apply to the data",
        examples=[{"event_type": "page_view", "platform": "web"}],
    )

    start_time: datetime | None = Field(
        None,
        description="Start of the time range for data (default: 24 hours ago)",
        examples=["2025-03-29T00:00:00Z"],
    )

    end_time: datetime | None = Field(
        None,
        description="End of the time range for data (default: current time)",
        examples=["2025-03-30T00:00:00Z"],
    )

    use_cache: bool = Field(True, description="Whether to use cached results if available")

    @model_validator(mode="after")
    def validate_time_range(self) -> "AnalyticsAggregationRequest":
        """
        Validate that start_time is before end_time if both are provided.

        If the time range is invalid, they will be swapped.
        """
        if self.start_time and self.end_time and self.start_time > self.end_time:
            self.start_time, self.end_time = self.end_time, self.start_time

        return self
