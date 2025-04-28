# -*- coding: utf-8 -*-
"""
Tests for the RetrieveAggregatedAnalyticsUseCase.

This module contains unit tests for retrieving and formatting aggregated
analytics data for dashboards and reporting.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from app.domain.utils.datetime_utils import UTC, now_utc

from app.domain.entities.analytics import AnalyticsAggregate
from app.application.use_cases.analytics.retrieve_aggregated_analytics import RetrieveAggregatedAnalyticsUseCase


@pytest.fixture
def mock_analytics_repository():
    """Create a mock analytics repository for testing."""
    repo = AsyncMock()

    # Set up the get_aggregates method to return mock data
    async def get_aggregates_mock(
        aggregate_type,
        dimensions,
        filters=None,
        start_time=None,
        end_time=None):
        # Generate some mock aggregates based on input params
        if aggregate_type == "error_type":
            raise ValueError("Simulated error in aggregation")

        if not dimensions or "event_type" in dimensions:
            return [
                AnalyticsAggregate(
                    dimensions={"event_type": "page_view"},
                    metrics={"count": 125, "avg_duration": 45.3},
                    time_period={"start": start_time, "end": end_time}
                ),
                AnalyticsAggregate(
                    dimensions={"event_type": "feature_usage"},
                    metrics={"count": 83, "avg_duration": 120.7},
                    time_period={"start": start_time, "end": end_time}
                )
            ]
                
        elif "user_role" in dimensions:
            return [
                AnalyticsAggregate(
                    dimensions={"user_role": "provider"},
                    metrics={"count": 210, "avg_actions": 15.2},
                    time_period={"start": start_time, "end": end_time}
                ),
                AnalyticsAggregate(
                    dimensions={"user_role": "admin"},
                    metrics={"count": 45, "avg_actions": 22.5},
                    time_period={"start": start_time, "end": end_time}
                )
            ]
                    
        else:
            # Default case
            return [
                AnalyticsAggregate(
                    dimensions={"dimension": "default"},
                    metrics={"count": 100},
                    time_period={"start": start_time, "end": end_time}
                )
            ]
                    

    repo.get_aggregates = get_aggregates_mock
    return repo

@pytest.fixture
def mock_cache_service():

    """Create a mock cache service for testing."""
    cache = AsyncMock()
    
    # Track cache keys and values
    cache_data = {}
    
    async def get_mock(key):
        return cache_data.get(key)

    async def set_mock(key, value, ttl=None):
        cache_data[key] = value
        return True

    cache.get = get_mock
    cache.set = set_mock
    
    # Attach the cache data for test inspection
    cache._cache_data = cache_data
    
    return cache

@pytest.fixture
def use_case(mock_analytics_repository, mock_cache_service):

    """Create the use case with mocked dependencies."""
    with patch('app.core.utils.logging.get_logger') as mock_logger:
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance
        
        use_case = RetrieveAggregatedAnalyticsUseCase(
            analytics_repository=mock_analytics_repository,
            cache_service=mock_cache_service
        )

        # Attach the mock logger for assertions
        use_case._logger = mock_logger_instance
        return use_case

@pytest.mark.db_required()
class TestRetrieveAggregatedAnalyticsUseCase:
    """Test suite for the RetrieveAggregatedAnalyticsUseCase."""

    @pytest.mark.asyncio
    async def test_execute_with_basic_parameters(
            self, use_case, mock_analytics_repository):
        """
        Test retrieving aggregated data with basic parameters.
        """
        # Arrange
        aggregate_type = "count"
        dimensions = ["event_type"]

        # Act
        result = await use_case.execute(
            aggregate_type=aggregate_type,
            dimensions=dimensions
        )

        # Assert
        assert len(result) == 2
        assert result[0].dimensions["event_type"] == "page_view"
        assert result[0].metrics["count"] == 125
        assert result[1].dimensions["event_type"] == "feature_usage"

        # Verify repository was called with correct parameters
        mock_analytics_repository.get_aggregates.assert_called_once()
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert call_args["aggregate_type"] == aggregate_type
        assert call_args["dimensions"] == dimensions

        # Verify appropriate logging
        use_case._logger.info.assert_any_call(
            f"Retrieving {aggregate_type} analytics",
            {"dimensions": dimensions,
            "time_range": f"{call_args['start_time']} to {call_args['end_time']}"}
        )

    @pytest.mark.asyncio
    async def test_execute_with_filters_and_time_range(
            self, use_case, mock_analytics_repository):
        """
        Test retrieving data with filters and custom time range.
        """
        # Arrange
        aggregate_type = "avg"
        dimensions = ["user_role"]
        filters = {"platform": "web", "browser": "chrome"}
        now = datetime.now(UTC)
        week_ago = now - timedelta(days=7)
        time_range = {"start": week_ago, "end": now}

        # Act
        result = await use_case.execute(
            aggregate_type=aggregate_type,
            dimensions=dimensions,
            filters=filters,
            time_range=time_range
        )

        # Assert
        assert len(result) == 2
        assert "user_role" in result[0].dimensions

        # Verify repository was called with correct parameters
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert call_args["aggregate_type"] == aggregate_type
        assert call_args["dimensions"] == dimensions
        assert "platform" in call_args["filters"]
        assert "browser" in call_args["filters"]
        assert call_args["start_time"] == week_ago
        assert call_args["end_time"] == now

    @pytest.mark.asyncio
    async def test_time_range_string_handling(
            self, use_case, mock_analytics_repository):
        """
        Test handling of string format time ranges.
        """
        # Arrange
        time_range = {
            "start": "2025-03-15T00:00:00",
            "end": "2025-03-30T00:00:00"
        }

        # Act
        result = await use_case.execute(
            aggregate_type="count",
            dimensions=["event_type"],
            time_range=time_range
        )

        # Assert
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert call_args["start_time"].year == 2025
        assert call_args["start_time"].month == 3
        assert call_args["start_time"].day == 15
        assert call_args["end_time"].year == 2025
        assert call_args["end_time"].month == 3
        assert call_args["end_time"].day == 30

    @pytest.mark.asyncio
    async def test_invalid_time_range_handling(
            self, use_case, mock_analytics_repository):
        """
        Test handling of invalid time ranges.
        """
        # Arrange - invalid time strings and reversed dates
        time_range = {
            "start": "2025-03-30T00:00:00",  # Later than end (will be swapped)
            "end": "not-a-date"  # Invalid date string
        }

        # Act
        result = await use_case.execute(
            aggregate_type="count",
            dimensions=["event_type"],
            time_range=time_range
        )

        # Assert - should use default end time and swap dates
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert call_args["start_time"].year == 2025
        assert call_args["start_time"].month == 3
        assert call_args["start_time"].day == 30
        # End time should be current time (can't test exact value)
        assert isinstance(call_args["end_time"], datetime)

    @pytest.mark.asyncio
    async def test_dimension_sanitization(
            self, use_case, mock_analytics_repository):
        """
        Test sanitization of dimension parameters.
        """
        # Arrange - include valid and invalid dimensions
        dimensions = ["event_type", "invalid_dimension", "user_role"]

        # Act
        result = await use_case.execute(
            aggregate_type="count",
            dimensions=dimensions
        )

        # Assert - should filter out invalid dimensions
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert "event_type" in call_args["dimensions"]
        assert "user_role" in call_args["dimensions"]
        assert "invalid_dimension" not in call_args["dimensions"]

    @pytest.mark.asyncio
    async def test_filter_sanitization(
            self, use_case, mock_analytics_repository):
        """
        Test sanitization of filter parameters.
        """
        # Arrange - include valid and invalid filters, and different types
        filters = {
            "event_type": "page_view",  # Valid
            "user_role": "admin",  # Valid
            "patient_name": "John Doe",  # PHI - should be filtered out
            "platform": 123  # Wrong type, should be converted to string
        }

        # Act
        result = await use_case.execute(
            aggregate_type="count",
            dimensions=["event_type"],
            filters=filters
        )

        # Assert - should sanitize filters
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert "event_type" in call_args["filters"]
        assert "user_role" in call_args["filters"]
        assert "patient_name" not in call_args["filters"]
        assert "platform" in call_args["filters"]
        assert isinstance(call_args["filters"]["platform"], str)

    @pytest.mark.asyncio
    async def test_caching_behavior(
            self,
            use_case,
            mock_analytics_repository,
            mock_cache_service):
        """
        Test caching of aggregation results.
        """
        # Arrange
        aggregate_type = "count"
        dimensions = ["event_type"]

        # Act - first call should hit the repository
        result1 = await use_case.execute(
            aggregate_type=aggregate_type,
            dimensions=dimensions,
            use_cache=True
        )

        # Repository should have been called
        assert mock_analytics_repository.get_aggregates.call_count == 1

        # Get the cache key that was used
        cache_keys = list(mock_cache_service._cache_data.keys())
        assert len(cache_keys) == 1
        cache_key = cache_keys[0]

        # Act - second call with same parameters should use cache
        result2 = await use_case.execute(
            aggregate_type=aggregate_type,
            dimensions=dimensions,
            use_cache=True
        )

        # Repository should not have been called again
        assert mock_analytics_repository.get_aggregates.call_count == 1

        # Cache retrieval should have been logged
        use_case._logger.info.assert_any_call(
            f"Retrieved cached analytics for {aggregate_type}",
            {"dimensions": dimensions}
        )

    @pytest.mark.asyncio
    async def test_cache_ttl_determination(self, use_case):
        """
        Test different TTL values based on query parameters.
        """
        # Historical data (older than 1 day)
        now = datetime.now(UTC)
        historical_start = now - timedelta(days=10)
        historical_end = now - timedelta(days=2)

        historical_ttl = use_case._get_cache_ttl(
            aggregate_type="count",
            start_time=historical_start,
            end_time=historical_end
        )

        # Recent data (within last hour)
        recent_start = now - timedelta(hours=1)
        recent_end = now

        recent_ttl = use_case._get_cache_ttl(
            aggregate_type="count",
            start_time=recent_start,
            end_time=recent_end
        )

        # Regular data (between recent and historical)
        regular_start = now - timedelta(hours=12)
        regular_end = now - timedelta(hours=2)

        regular_ttl = use_case._get_cache_ttl(
            aggregate_type="count",
            start_time=regular_start,
            end_time=regular_end
        )

        # Assert appropriate TTLs
        assert historical_ttl == 3600 * 24  # 24 hours for historical data
        assert recent_ttl == 300  # 5 minutes for recent data
        assert regular_ttl == 3600  # 1 hour for regular data

    @pytest.mark.asyncio
    async def test_cache_key_generation(self, use_case):
        """
        Test generation of cache keys from parameters.
        """
        # Arrange
        aggregate_type = "count"
        dimensions = ["event_type", "user_role"]
        filters = {"platform": "web", "browser": "chrome"}
        now = datetime.now(UTC)
        week_ago = now - timedelta(days=7)

        # Act
        key = use_case._generate_cache_key(
            aggregate_type=aggregate_type,
            dimensions=dimensions,
            filters=filters,
            start_time=week_ago,
            end_time=now
        )

        # Assert
        assert "analytics" in key
        assert aggregate_type in key
        assert "event_type-user_role" in key or "user_role-event_type" in key
        assert "browser:chrome" in key or "platform:web" in key
        assert "from:" in key
        assert "to:" in key

        # Different parameters should generate different keys
        key2 = use_case._generate_cache_key(
            aggregate_type="sum",
            dimensions=dimensions,
            filters=filters,
            start_time=week_ago,
            end_time=now
        )

        assert key != key2

    @pytest.mark.asyncio
    async def test_empty_dimensions_default(
            self, use_case, mock_analytics_repository):
        """
        Test default dimension when empty list provided.
        """
        # Arrange
        dimensions = []

        # Act
        result = await use_case.execute(
            aggregate_type="count",
            dimensions=dimensions
        )

        # Assert - should default to ["event_type"]
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert call_args["dimensions"] == ["event_type"]

    @pytest.mark.asyncio
    async def test_very_large_time_range_limit(
            self, use_case, mock_analytics_repository):
        """
        Test limiting of very large time ranges.
        """
        # Arrange - huge time range (2 years)
        now = datetime.now(UTC)
        start = now - timedelta(days=730)
        time_range = {"start": start, "end": now}

        # Act
        result = await use_case.execute(
            aggregate_type="count",
            dimensions=["event_type"],
            time_range=time_range
        )

        # Assert - should be limited to 1 year
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        actual_range = call_args["end_time"] - call_args["start_time"]
        assert actual_range.days <= 366  # Account for leap years
