"""
Retrieve Aggregated Analytics Use Case.

This module contains the use case for retrieving and formatting aggregated
analytics data for dashboards and reporting.
"""

from datetime import datetime, timedelta
from typing import Any

from app.application.interfaces.repositories.analytics_repository import (
    AnalyticsRepository,
)
from app.application.interfaces.services.cache_service import CacheService
from app.core.utils.logging import get_logger
from app.domain.entities.analytics import AnalyticsAggregate
from app.domain.utils.datetime_utils import UTC


class RetrieveAggregatedAnalyticsUseCase:
    """
    Retrieve aggregated analytics data for dashboards and reports.

    This use case is responsible for fetching pre-aggregated analytics data
    or computing aggregations on-demand. It provides multiple aggregation types
    and dimensions with efficient caching.
    """

    def __init__(
        self, analytics_repository: AnalyticsRepository, cache_service: CacheService
    ) -> None:
        """
        Initialize the use case with required dependencies.

        Args:
            analytics_repository: Repository for retrieving analytics data
            cache_service: Service for caching computed aggregations
        """
        self.analytics_repository = analytics_repository
        self.cache_service = cache_service
        self.logger = get_logger(__name__)

    async def execute(
        self,
        aggregate_type: str,
        dimensions: list[str],
        filters: dict[str, Any] | None = None,
        time_range: dict[str, datetime | str] | None = None,
        use_cache: bool = True,
    ) -> list[AnalyticsAggregate]:
        """
        Retrieve aggregated analytics data.

        Args:
            aggregate_type: Type of aggregation (count, avg, sum, etc.)
            dimensions: Dimensions to group by (e.g., event_type, user_role)
            filters: Optional filters to apply to the data
            time_range: Optional time range for the data
            use_cache: Whether to use cached results if available

        Returns:
            A list of AnalyticsAggregate objects with the aggregated data
        """
        # Sanitize and validate inputs
        sanitized_dimensions = self._sanitize_dimensions(dimensions)
        sanitized_filters = self._sanitize_filters(filters or {})

        # Resolve time range
        start_time, end_time = self._resolve_time_range(time_range)

        # Check cache if enabled
        if use_cache:
            cache_key = self._generate_cache_key(
                aggregate_type=aggregate_type,
                dimensions=sanitized_dimensions,
                filters=sanitized_filters,
                start_time=start_time,
                end_time=end_time,
            )

            cached_result = await self.cache_service.get(cache_key)
            if cached_result:
                self.logger.info(
                    f"Retrieved cached analytics for {aggregate_type}",
                    {"dimensions": sanitized_dimensions},
                )
                return cached_result

        # Get aggregated data from repository
        self.logger.info(
            f"Retrieving {aggregate_type} analytics",
            {
                "dimensions": sanitized_dimensions,
                "time_range": f"{start_time} to {end_time}",
            },
        )

        aggregates = await self.analytics_repository.get_aggregates(
            aggregate_type=aggregate_type,
            dimensions=sanitized_dimensions,
            filters=sanitized_filters,
            start_time=start_time,
            end_time=end_time,
        )

        # Cache the result if caching is enabled
        if use_cache and aggregates:
            cache_key = self._generate_cache_key(
                aggregate_type=aggregate_type,
                dimensions=sanitized_dimensions,
                filters=sanitized_filters,
                start_time=start_time,
                end_time=end_time,
            )

            # Determine appropriate cache TTL based on query type
            ttl = self._get_cache_ttl(aggregate_type, start_time, end_time)

            await self.cache_service.set(key=cache_key, value=aggregates, ttl=ttl)

        return aggregates

    def _sanitize_dimensions(self, dimensions: list[str]) -> list[str]:
        """
        Sanitize and validate dimension names.

        Args:
            dimensions: List of dimension names to sanitize

        Returns:
            Sanitized list of dimension names
        """
        allowed_dimensions = {
            "event_type",
            "user_id",
            "session_id",
            "timestamp",
            "date",
            "hour",
            "day_of_week",
            "month",
            "year",
            "user_role",
            "platform",
            "device",
            "browser",
            "patient_id",
            "provider_id",
            "clinic_id",
        }

        # Filter to only allowed dimensions
        sanitized = [dim for dim in dimensions if dim in allowed_dimensions]

        # If empty, use event_type as default dimension
        if not sanitized:
            sanitized = ["event_type"]

        return sanitized

    def _sanitize_filters(self, filters: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize and validate filter values.

        This method ensures that filters don't contain PHI and
        conform to expected types.

        Args:
            filters: Dictionary of filters to sanitize

        Returns:
            Sanitized filters dictionary
        """
        # Define allowed filter fields and their types
        allowed_filters = {
            "event_type": str,
            "user_role": str,
            "platform": str,
            "device": str,
            "browser": str,
        }

        sanitized_filters = {}

        for key, value in filters.items():
            # Skip if key not in allowed filters
            if key not in allowed_filters:
                continue

            # Ensure value is of correct type
            expected_type = allowed_filters[key]
            if not isinstance(value, expected_type):
                try:
                    value = expected_type(value)
                except (ValueError, TypeError):
                    continue

            sanitized_filters[key] = value

        return sanitized_filters

    def _resolve_time_range(
        self, time_range: dict[str, datetime | str] | None
    ) -> tuple[datetime, datetime]:
        """
        Resolve and validate time range for the query.

        Args:
            time_range: Dictionary with start_time and end_time keys

        Returns:
            Tuple of (start_time, end_time) as datetime objects with UTC timezone

        Raises:
            ValueError: If time_range is invalid and cannot be fixed
        """
        now = datetime.now(UTC)

        # Default to last 24 hours if no time range provided
        if not time_range:
            return now - timedelta(days=1), now

        # Extract start and end times from the modern format (start_time/end_time keys)
        start_time = time_range.get("start_time") or time_range.get("start")
        end_time = time_range.get("end_time") or time_range.get("end")

        # Convert string times to datetime objects
        if isinstance(start_time, str):
            try:
                start_time = datetime.fromisoformat(start_time)
                # Ensure timezone info
                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=UTC)
            except ValueError:
                self.logger.warning(f"Invalid start time format: {start_time}")
                start_time = now - timedelta(days=1)

        if isinstance(end_time, str):
            try:
                end_time = datetime.fromisoformat(end_time)
                # Ensure timezone info
                if end_time.tzinfo is None:
                    end_time = end_time.replace(tzinfo=UTC)
            except ValueError:
                self.logger.warning(f"Invalid end time format: {end_time}")
                end_time = now

        # Set defaults if values are None
        if start_time is None:
            start_time = now - timedelta(days=1)

        if end_time is None:
            end_time = now

        # Ensure both have timezone info
        if getattr(start_time, "tzinfo", None) is None:
            start_time = start_time.replace(tzinfo=UTC)

        if getattr(end_time, "tzinfo", None) is None:
            end_time = end_time.replace(tzinfo=UTC)

        # Ensure start is before end and raise a ValueError if the time range is clearly invalid
        if start_time > end_time:
            if time_range.get("start_time") and time_range.get("end_time"):
                # If explicit start_time and end_time were provided, this is an error
                # since we have intentionally provided invalid data
                raise ValueError("Invalid time range: start_time is after end_time")

            # Otherwise swap them to fix the issue
            start_time, end_time = end_time, start_time

        # Limit time range to reasonable bounds (e.g., max 1 year)
        max_range = timedelta(days=365)
        if end_time - start_time > max_range:
            start_time = end_time - max_range

        return start_time, end_time

    def _generate_cache_key(
        self,
        aggregate_type: str,
        dimensions: list[str],
        filters: dict[str, Any],
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """
        Generate a cache key for the query parameters.

        Args:
            aggregate_type: Type of aggregation
            dimensions: Dimensions used for grouping
            filters: Applied filters
            start_time: Start of time range
            end_time: End of time range

        Returns:
            A unique cache key string
        """
        # Format times as ISO strings truncated to minutes
        start_str = start_time.strftime("%Y-%m-%dT%H:%M")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M")

        # Sort dimensions and concatenate
        dim_str = "-".join(sorted(dimensions))

        # Sort filter keys and format as key:value pairs
        filter_items = sorted(filters.items())
        filter_str = "-".join(f"{k}:{v}" for k, v in filter_items)

        # Build cache key
        key_parts = [
            "analytics",
            aggregate_type,
            dim_str,
            filter_str if filter_str else "nofilter",
            f"from:{start_str}",
            f"to:{end_str}",
        ]

        return ":".join(key_parts)

    def _get_cache_ttl(
        self, aggregate_type: str, start_time: datetime, end_time: datetime
    ) -> int:
        """
        Determine appropriate cache TTL based on query parameters.

        Historical data can be cached longer than recent data.

        Args:
            aggregate_type: Type of aggregation
            start_time: Start time of the query range
            end_time: End time of the query range

        Returns:
            TTL in seconds for the cache entry
        """
        now = datetime.now(UTC)

        # Ensure we have timezone-aware datetimes for comparison
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=UTC)

        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=UTC)

        # Historical data (more than 1 day old)
        if end_time < now - timedelta(days=1):
            # Cache historical data longer (1 hour)
            return 60 * 60

        # Recent data that's not real-time
        if end_time < now - timedelta(hours=1):
            # Cache recent data for 5 minutes
            return 5 * 60

        # Real-time or near real-time data
        # Cache for shorter period (30 seconds)
        return 30
