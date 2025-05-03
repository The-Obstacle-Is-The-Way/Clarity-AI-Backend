# -*- coding: utf-8 -*-
"""
Use Case Dependencies for FastAPI.

This module provides dependency functions for injecting use case instances
into FastAPI endpoints, following the Dependency Injection pattern.
"""

from fastapi import Depends

from app.application.use_cases.analytics.process_analytics_event import ProcessAnalyticsEventUseCase
from app.application.use_cases.analytics.batch_process_analytics import BatchProcessAnalyticsUseCase
from app.application.use_cases.analytics.retrieve_aggregated_analytics import RetrieveAggregatedAnalyticsUseCase

from app.presentation.api.dependencies.repositories import (
    get_analytics_repository,
)
from app.presentation.api.dependencies.services import (
    get_cache_service,
)


async def get_process_analytics_event_use_case(
    analytics_repository = Depends(get_analytics_repository),
    cache_service = Depends(get_cache_service)
) -> ProcessAnalyticsEventUseCase:
    """
    Provide an instance of the ProcessAnalyticsEventUseCase.
    
    Args:
        analytics_repository: Repository for analytics data
        cache_service: Service for caching
        
    Returns:
        An instance of ProcessAnalyticsEventUseCase
    """
    return ProcessAnalyticsEventUseCase(
        analytics_repository=analytics_repository,
        cache_service=cache_service
    )


async def get_batch_process_analytics_use_case(
    analytics_repository = Depends(get_analytics_repository),
    cache_service = Depends(get_cache_service),
    event_processor = Depends(get_process_analytics_event_use_case)
) -> BatchProcessAnalyticsUseCase:
    """
    Provide an instance of the BatchProcessAnalyticsUseCase.
    
    Args:
        analytics_repository: Repository for analytics data
        cache_service: Service for caching
        event_processor: Use case for processing individual events
        
    Returns:
        An instance of BatchProcessAnalyticsUseCase
    """
    return BatchProcessAnalyticsUseCase(
        analytics_repository=analytics_repository,
        cache_service=cache_service,
        event_processor=event_processor
    )


async def get_retrieve_aggregated_analytics_use_case(
    analytics_repository = Depends(get_analytics_repository),
    cache_service = Depends(get_cache_service)
) -> RetrieveAggregatedAnalyticsUseCase:
    """
    Provide an instance of the RetrieveAggregatedAnalyticsUseCase.
    
    Args:
        analytics_repository: Repository for analytics data
        cache_service: Service for caching
        
    Returns:
        An instance of RetrieveAggregatedAnalyticsUseCase
    """
    return RetrieveAggregatedAnalyticsUseCase(
        analytics_repository=analytics_repository,
        cache_service=cache_service
    )