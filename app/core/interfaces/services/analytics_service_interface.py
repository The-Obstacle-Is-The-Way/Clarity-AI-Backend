"""
Analytics service interface definition.

This module defines the abstract interface for analytics services
following clean architecture principles with proper separation of concerns.
The analytics service provides data analysis capabilities across the platform.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID


class AnalyticsServiceInterface(ABC):
    """
    Abstract interface for analytics services.
    
    This interface defines the contract for analytics operations,
    allowing for different implementations while maintaining a
    consistent interface throughout the application.
    """
    
    @abstractmethod
    async def track_event(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        user_id: Optional[Union[str, UUID]] = None,
        session_id: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> bool:
        """
        Track an analytics event.
        
        Args:
            event_type: Type of event to track
            event_data: Data associated with the event
            user_id: Optional ID of the user who triggered the event
            session_id: Optional session identifier
            timestamp: Optional custom timestamp (defaults to now)
            
        Returns:
            True if tracked successfully, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_user_metrics(
        self,
        user_id: Union[str, UUID],
        start_date: datetime,
        end_date: datetime,
        metrics: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Get metrics for a specific user.
        
        Args:
            user_id: ID of the user
            start_date: Start of the time range
            end_date: End of the time range
            metrics: Optional list of specific metrics to retrieve
            
        Returns:
            Dictionary of metrics and their values
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_system_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        metrics: Optional[List[str]] = None,
        granularity: str = "day"
    ) -> Dict[str, Any]:
        """
        Get system-wide metrics.
        
        Args:
            start_date: Start of the time range
            end_date: End of the time range
            metrics: Optional list of specific metrics to retrieve
            granularity: Time granularity for aggregation (hour, day, week, month)
            
        Returns:
            Dictionary of metrics and their values
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_usage_report(
        self,
        start_date: datetime,
        end_date: datetime,
        group_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a usage report for the platform.
        
        Args:
            start_date: Start of the time range
            end_date: End of the time range
            group_by: Optional grouping field (user, feature, etc.)
            
        Returns:
            Usage report data
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_feature_usage(
        self,
        feature_name: str,
        start_date: datetime,
        end_date: datetime,
        granularity: str = "day"
    ) -> Dict[str, Any]:
        """
        Get usage statistics for a specific feature.
        
        Args:
            feature_name: Name of the feature to analyze
            start_date: Start of the time range
            end_date: End of the time range
            granularity: Time granularity for aggregation
            
        Returns:
            Feature usage statistics
        """
        raise NotImplementedError