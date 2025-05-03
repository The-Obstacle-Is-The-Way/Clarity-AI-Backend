# -*- coding: utf-8 -*-
"""
Analytics API schemas module.

This module exports all the request and response schemas used by the analytics
endpoints in the Novamind Digital Twin platform.
"""

from app.presentation.api.schemas.analytics.requests import (
    AnalyticsEventCreateRequest,
    AnalyticsEventsBatchRequest,
    AnalyticsAggregationRequest
)

from app.presentation.api.schemas.analytics.responses import (
    AnalyticsEventResponse,
    AnalyticsEventsBatchResponse,
    AnalyticsAggregateResponse,
    AnalyticsAggregatesListResponse
)

__all__ = [
    'AnalyticsEventCreateRequest',
    'AnalyticsEventsBatchRequest',
    'AnalyticsAggregationRequest',
    'AnalyticsEventResponse',
    'AnalyticsEventsBatchResponse',
    'AnalyticsAggregateResponse',
    'AnalyticsAggregatesListResponse',
]