"""
Analytics API schemas module.

This module exports all the request and response schemas used by the analytics
endpoints in the Novamind Digital Twin platform.
"""

from app.presentation.api.schemas.analytics.requests import (
    AnalyticsAggregationRequest,
    AnalyticsEventCreateRequest,
    AnalyticsEventsBatchRequest,
)
from app.presentation.api.schemas.analytics.responses import (
    AnalyticsAggregateResponse,
    AnalyticsAggregatesListResponse,
    AnalyticsEventResponse,
    AnalyticsEventsBatchResponse,
)

__all__ = [
    "AnalyticsAggregateResponse",
    "AnalyticsAggregatesListResponse",
    "AnalyticsAggregationRequest",
    "AnalyticsEventCreateRequest",
    "AnalyticsEventResponse",
    "AnalyticsEventsBatchRequest",
    "AnalyticsEventsBatchResponse",
]
