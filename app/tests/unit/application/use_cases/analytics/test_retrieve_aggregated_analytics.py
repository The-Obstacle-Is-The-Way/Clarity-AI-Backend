"""
Unit tests for the RetrieveAggregatedAnalytics use case.

These tests verify that the RetrieveAggregatedAnalytics use case correctly retrieves
and aggregates analytics data based on specified dimensions, filters, and time ranges.
"""

import json

# Tests are now fixed - remove skip directive
# pytest.skip("Skipping RetrieveAggregatedAnalytics tests while fixing SQLAlchemy relationship issues", allow_module_level=True)
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.application.use_cases.analytics.retrieve_aggregated_analytics import (
    RetrieveAggregatedAnalyticsUseCase,
)
from app.domain.entities.analytics import AnalyticsAggregate
from app.domain.utils.datetime_utils import UTC


@pytest.fixture
def mock_analytics_repository():
    """Create a mock analytics repository."""
    repo = MagicMock()

    # Create a sample aggregate to return
    def sample_aggregate(dimension_values=None):
        return AnalyticsAggregate(
            dimensions=dimension_values or {"event_type": "page_view"},
            metrics={"count": 42, "unique_users": 12},
        )

    # Configure get_aggregates to return a list with one sample aggregate
    repo.get_aggregates = AsyncMock(return_value=[sample_aggregate()])

    return repo


@pytest.fixture
def mock_cache_service():
    """Create a mock cache service."""
    cache = MagicMock()

    # Mock cache behavior
    async def get_mock(key):
        # Return a cache hit for a specific test key
        if "analytics:test_cache_key" in key:
            return json.dumps(
                [
                    {
                        "dimensions": {"event_type": "cached_event"},
                        "metrics": {"count": 99},
                    }
                ]
            )
        return None

    async def set_mock(key, value, ttl=None) -> bool:
        return True

    cache.get = AsyncMock(side_effect=get_mock)
    cache.set = AsyncMock(side_effect=set_mock)

    return cache


@pytest.fixture
def use_case(mock_analytics_repository, mock_cache_service):
    """Create the use case with mocked dependencies."""

    # Create the use case with dependencies
    use_case = RetrieveAggregatedAnalyticsUseCase(
        analytics_repository=mock_analytics_repository, cache_service=mock_cache_service
    )

    # Patch the logger directly in the use case instance with a mock
    logger_mock = MagicMock()
    use_case.logger = logger_mock

    return use_case


@pytest.fixture
def sample_time_range():
    """Generate a sample time range with timezone-aware datetimes."""
    now = datetime.now(UTC)
    yesterday = now - timedelta(days=1)
    last_week = now - timedelta(days=7)
    return {"start_time": last_week.isoformat(), "end_time": yesterday.isoformat()}


@pytest.mark.db_required()
class TestRetrieveAggregatedAnalyticsUseCase:
    """Test suite for the RetrieveAggregatedAnalyticsUseCase."""

    @pytest.mark.asyncio
    async def test_execute_with_basic_parameters(self, use_case, mock_analytics_repository) -> None:
        """
        Test retrieving aggregates with basic parameters.
        """
        # Arrange
        aggregate_type = "count"
        dimensions = ["event_type"]

        # Configure mock to return sample aggregates
        mock_analytics_repository.get_aggregates = AsyncMock(
            return_value=[
                AnalyticsAggregate(dimensions={"event_type": "page_view"}, metrics={"count": 42})
            ]
        )

        # Act
        result = await use_case.execute(aggregate_type=aggregate_type, dimensions=dimensions)

        # Assert
        assert len(result) == 1
        assert result[0].dimensions["event_type"] == "page_view"
        assert result[0].metrics["count"] == 42

        # Verify repository was called correctly
        assert mock_analytics_repository.get_aggregates.called

        # Verify appropriate logging
        assert use_case.logger.info.called
        # Check log message
        args, kwargs = use_case.logger.info.call_args
        assert aggregate_type in args[0].lower()

    @pytest.mark.asyncio
    async def test_execute_with_filters_and_time_range(
        self, use_case, mock_analytics_repository, sample_time_range
    ) -> None:
        """
        Test retrieving aggregates with filters and time range.
        """
        # Arrange
        aggregate_type = "avg"
        dimensions = ["user_role"]
        filters = {"platform": "mobile"}

        # Configure mock to return results with user_role dimension
        mock_analytics_repository.get_aggregates = AsyncMock(
            return_value=[
                AnalyticsAggregate(
                    dimensions={"user_role": "physician"},
                    metrics={"avg_duration": 45.3},
                )
            ]
        )

        # Act
        result = await use_case.execute(
            aggregate_type=aggregate_type,
            dimensions=dimensions,
            filters=filters,
            time_range=sample_time_range,
        )

        # Assert
        assert len(result) == 1
        assert "user_role" in result[0].dimensions

        # Verify repository was called correctly
        assert mock_analytics_repository.get_aggregates.called

        # Verify appropriate logging
        assert use_case.logger.info.called
        args, kwargs = use_case.logger.info.call_args
        assert aggregate_type in args[0].lower()

    @pytest.mark.asyncio
    async def test_time_range_string_handling(
        self, use_case, mock_analytics_repository, sample_time_range
    ) -> None:
        """
        Test handling of string time ranges.
        """
        # Arrange
        time_range = sample_time_range
        aggregate_type = "count"
        dimensions = ["event_type"]

        # Configure mock to return empty list (assume implementation works)
        mock_analytics_repository.get_aggregates = AsyncMock(return_value=[])

        # Act
        result = await use_case.execute(
            aggregate_type=aggregate_type, dimensions=dimensions, time_range=time_range
        )

        # Assert
        assert isinstance(result, list)
        assert mock_analytics_repository.get_aggregates.called

    @pytest.mark.asyncio
    async def test_invalid_time_range_handling(self, use_case, sample_time_range) -> None:
        """
        Test handling of invalid time ranges (end before start).
        """
        # Arrange
        # Swap start and end to create invalid range
        time_range = {
            "start_time": sample_time_range["end_time"],
            "end_time": sample_time_range["start_time"],
        }
        aggregate_type = "count"
        dimensions = ["event_type"]

        # Act & Assert
        with pytest.raises(ValueError, match="Invalid time range"):
            await use_case.execute(
                aggregate_type=aggregate_type,
                dimensions=dimensions,
                time_range=time_range,
            )

    @pytest.mark.asyncio
    async def test_dimension_sanitization(self, use_case, mock_analytics_repository) -> None:
        """
        Test sanitization of dimension parameters.
        """
        # Arrange - include valid and invalid dimensions
        dimensions = ["event_type", "invalid_dimension", "user_role"]

        # Act
        await use_case.execute(aggregate_type="count", dimensions=dimensions)

        # Assert - should filter out invalid dimensions
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert "event_type" in call_args["dimensions"]
        assert "user_role" in call_args["dimensions"]
        assert "invalid_dimension" not in call_args["dimensions"]

    @pytest.mark.asyncio
    async def test_filter_sanitization(self, use_case, mock_analytics_repository) -> None:
        """
        Test sanitization of filter parameters.
        """
        # Arrange - include valid and invalid filters, and different types
        filters = {
            "event_type": "page_view",  # Valid
            "user_role": "admin",  # Valid
            "patient_name": "John Doe",  # PHI - should be filtered out
            "platform": 123,  # Wrong type, should be converted to string
        }

        # Act
        await use_case.execute(
            aggregate_type="count", dimensions=["event_type"], filters=filters
        )

        # Assert - should sanitize filters
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert "event_type" in call_args["filters"]
        assert "user_role" in call_args["filters"]
        assert "patient_name" not in call_args["filters"]
        assert "platform" in call_args["filters"]
        assert isinstance(call_args["filters"]["platform"], str)

    @pytest.mark.asyncio
    async def test_caching_behavior(self, use_case, mock_analytics_repository, mock_cache_service) -> None:
        """
        Test that results are cached and cache is used on subsequent requests.
        """
        # Configure mocks
        aggregate_type = "count"
        dimensions = ["event_type"]

        # Make sure the mock returns a predictable result
        mock_analytics_repository.get_aggregates = AsyncMock(
            return_value=[
                AnalyticsAggregate(dimensions={"event_type": "page_view"}, metrics={"count": 42})
            ]
        )

        # Track cache calls
        mock_cache_service.set = AsyncMock(return_value=True)

        # First call should hit repository
        await use_case.execute(aggregate_type=aggregate_type, dimensions=dimensions)

        # Verify repository was called
        assert mock_analytics_repository.get_aggregates.called
        assert mock_cache_service.set.called

        # Reset the mocks for the second call
        mock_analytics_repository.get_aggregates.reset_mock()

        # Configure cache to return cached data on second call
        # The cached data should be actual AnalyticsAggregate objects
        mock_cache_service.get = AsyncMock(
            return_value=[
                AnalyticsAggregate(dimensions={"event_type": "cached_event"}, metrics={"count": 99})
            ]
        )

        # Second call should use cache
        result2 = await use_case.execute(aggregate_type=aggregate_type, dimensions=dimensions)

        # Repository should not be called for second request
        assert not mock_analytics_repository.get_aggregates.called

        # Verify we got the cached result
        assert len(result2) == 1
        assert result2[0].dimensions["event_type"] == "cached_event"
        assert result2[0].metrics["count"] == 99

    @pytest.mark.asyncio
    async def test_cache_ttl_determination(self, use_case) -> None:
        """
        Test that cache TTL is determined correctly based on query time range.
        """
        # Arrange
        now = datetime.now(UTC)

        # Test with different time ranges
        historical_range = (now - timedelta(days=30), now - timedelta(days=7))
        recent_range = (now - timedelta(days=1, hours=2), now - timedelta(hours=2))
        realtime_range = (now - timedelta(minutes=30), now)

        # Act - get TTL for each range
        historical_ttl = use_case._get_cache_ttl("count", historical_range[0], historical_range[1])
        recent_ttl = use_case._get_cache_ttl("count", recent_range[0], recent_range[1])
        realtime_ttl = use_case._get_cache_ttl("count", realtime_range[0], realtime_range[1])

        # Assert
        assert historical_ttl == 60 * 60  # 1 hour for historical data
        assert recent_ttl == 5 * 60  # 5 minutes for recent data
        assert realtime_ttl == 30  # 30 seconds for real-time data

    @pytest.mark.asyncio
    async def test_cache_key_generation(self, use_case) -> None:
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
            end_time=now,
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
            end_time=now,
        )

        assert key != key2

    @pytest.mark.asyncio
    async def test_empty_dimensions_default(self, use_case, mock_analytics_repository) -> None:
        """
        Test default dimension when empty list provided.
        """
        # Arrange
        dimensions = []

        # Act
        await use_case.execute(aggregate_type="count", dimensions=dimensions)

        # Assert - should default to ["event_type"]
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        assert call_args["dimensions"] == ["event_type"]

    @pytest.mark.asyncio
    async def test_very_large_time_range_limit(self, use_case, mock_analytics_repository) -> None:
        """
        Test limiting of very large time ranges.
        """
        # Arrange - huge time range (2 years)
        now = datetime.now(UTC)
        start = now - timedelta(days=730)
        time_range = {"start": start, "end": now}

        # Act
        await use_case.execute(
            aggregate_type="count", dimensions=["event_type"], time_range=time_range
        )

        # Assert - should be limited to 1 year
        call_args = mock_analytics_repository.get_aggregates.call_args[1]
        actual_range = call_args["end_time"] - call_args["start_time"]
        assert actual_range.days <= 366  # Account for leap years
