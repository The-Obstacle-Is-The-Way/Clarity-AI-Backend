"""
SQLAlchemy Analytics Repository Implementation.

This module implements the AnalyticsRepository interface using SQLAlchemy
as the ORM for database operations.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.interfaces.repositories.analytics_repository import (
    AnalyticsRepository,
)
from app.core.utils.logging import get_logger
from app.domain.entities.analytics import AnalyticsAggregate, AnalyticsEvent
from app.domain.utils.datetime_utils import UTC
from app.infrastructure.persistence.sqlalchemy.models.analytics import (
    AnalyticsAggregateModel,
    AnalyticsEventModel,
)

logger = get_logger(__name__)


class SQLAlchemyAnalyticsRepository(AnalyticsRepository):
    """
    SQLAlchemy implementation of the AnalyticsRepository interface.

    This repository handles all database operations for analytics data
    using SQLAlchemy ORM.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize the repository with a database session.

        Args:
            session: SQLAlchemy async session for database operations
        """
        self._session = session
        self._logger = logger

    async def save_event(self, event: AnalyticsEvent) -> AnalyticsEvent:
        """
        Save an analytics event to the database.

        Args:
            event: The analytics event to save

        Returns:
            The saved event with assigned ID

        Raises:
            Exception: If database operation fails
        """
        try:
            # Convert domain entity to ORM model
            model = AnalyticsEventModel(
                event_type=event.event_type,
                event_data=event.event_data,
                user_id=event.user_id,
                session_id=event.session_id,
                timestamp=event.timestamp or datetime.now(UTC),
                processed_at=datetime.now(UTC),
            )

            # Add to session and flush to get ID
            self._session.add(model)
            await self._session.flush()

            # Return domain entity with new ID
            return AnalyticsEvent(
                event_id=str(model.id),
                event_type=model.event_type,
                event_data=model.event_data,
                user_id=model.user_id,
                session_id=model.session_id,
                timestamp=model.timestamp,
            )

        except SQLAlchemyError as e:
            self._logger.error(f"Error saving analytics event: {e!s}")
            raise

    async def save_events(self, events: list[AnalyticsEvent]) -> list[AnalyticsEvent]:
        """
        Save multiple analytics events in a batch.

        Args:
            events: List of analytics events to save

        Returns:
            List of saved events with assigned IDs

        Raises:
            Exception: If database operation fails
        """
        try:
            # Convert all domain entities to ORM models
            models = []
            now = datetime.now(UTC)

            for event in events:
                model = AnalyticsEventModel(
                    event_type=event.event_type,
                    event_data=event.event_data,
                    user_id=event.user_id,
                    session_id=event.session_id,
                    timestamp=event.timestamp or now,
                    processed_at=now,
                )
                models.append(model)

            # Add all to session and flush to get IDs
            self._session.add_all(models)
            await self._session.flush()

            # Convert back to domain entities with IDs
            result = []
            for model in models:
                result.append(
                    AnalyticsEvent(
                        event_id=str(model.id),
                        event_type=model.event_type,
                        event_data=model.event_data,
                        user_id=model.user_id,
                        session_id=model.session_id,
                        timestamp=model.timestamp,
                    )
                )

            return result

        except SQLAlchemyError as e:
            self._logger.error(f"Error saving batch of analytics events: {e!s}")
            raise

    async def get_event(self, event_id: str) -> AnalyticsEvent | None:
        """
        Get a specific analytics event by ID.

        Args:
            event_id: The ID of the event to retrieve

        Returns:
            The analytics event if found, None otherwise

        Raises:
            Exception: If database operation fails
        """
        try:
            # Query for the event
            stmt = select(AnalyticsEventModel).where(AnalyticsEventModel.id == event_id)
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            # Return None if not found
            if model is None:
                return None

            # Convert ORM model to domain entity
            return AnalyticsEvent(
                event_id=str(model.id),
                event_type=model.event_type,
                event_data=model.event_data,
                user_id=model.user_id,
                session_id=model.session_id,
                timestamp=model.timestamp,
            )

        except SQLAlchemyError as e:
            self._logger.error(f"Error retrieving analytics event: {e!s}")
            raise

    async def get_events(
        self,
        filters: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[AnalyticsEvent]:
        """
        Get analytics events matching the specified criteria.

        Args:
            filters: Optional dictionary of field/value filters
            start_time: Optional start of time range
            end_time: Optional end of time range
            limit: Optional maximum number of results
            offset: Optional offset for pagination

        Returns:
            List of matching analytics events

        Raises:
            Exception: If database operation fails
        """
        try:
            # Build the query
            stmt = select(AnalyticsEventModel)

            # Apply filters
            if filters:
                conditions = []
                for field, value in filters.items():
                    if field == "event_type":
                        conditions.append(AnalyticsEventModel.event_type == value)
                    elif field == "user_id":
                        conditions.append(AnalyticsEventModel.user_id == value)
                    elif field == "session_id":
                        conditions.append(AnalyticsEventModel.session_id == value)

                if conditions:
                    stmt = stmt.where(and_(*conditions))

            # Apply time range
            if start_time:
                stmt = stmt.where(AnalyticsEventModel.timestamp >= start_time)
            if end_time:
                stmt = stmt.where(AnalyticsEventModel.timestamp <= end_time)

            # Apply pagination
            stmt = stmt.order_by(AnalyticsEventModel.timestamp.desc())
            if limit is not None:
                stmt = stmt.limit(limit)
            if offset is not None:
                stmt = stmt.offset(offset)

            # Execute query
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            # Convert ORM models to domain entities
            return [
                AnalyticsEvent(
                    event_id=str(model.id),
                    event_type=model.event_type,
                    event_data=model.event_data,
                    user_id=model.user_id,
                    session_id=model.session_id,
                    timestamp=model.timestamp,
                )
                for model in models
            ]

        except SQLAlchemyError as e:
            self._logger.error(f"Error retrieving analytics events: {e!s}")
            raise

    async def get_aggregates(
        self,
        aggregate_type: str,
        dimensions: list[str],
        filters: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[AnalyticsAggregate]:
        """
        Get aggregated analytics data.

        Args:
            aggregate_type: Type of aggregation (count, sum, avg, etc.)
            dimensions: Fields to group by
            filters: Optional filters to apply
            start_time: Optional start of time range
            end_time: Optional end of time range

        Returns:
            List of analytics aggregates

        Raises:
            Exception: If database operation fails or unsupported aggregation
        """
        try:
            # Validate dimensions
            valid_dimensions = ["event_type", "user_id", "session_id", "date"]
            dimensions = [d for d in dimensions if d in valid_dimensions]

            # Default to event_type if no valid dimensions
            if not dimensions:
                dimensions = ["event_type"]

            # Build the query for different aggregate types
            if aggregate_type.lower() == "count":
                return await self._get_count_aggregates(dimensions, filters, start_time, end_time)
            elif aggregate_type.lower() in ["sum", "avg"]:
                # These would require specific field to aggregate
                # For now, we'll implement count only
                self._logger.warning(f"Unsupported aggregate type: {aggregate_type}")
                return []
            else:
                self._logger.warning(f"Unsupported aggregate type: {aggregate_type}")
                return []

        except SQLAlchemyError as e:
            self._logger.error(f"Error retrieving analytics aggregates: {e!s}")
            raise

    async def _get_count_aggregates(
        self,
        dimensions: list[str],
        filters: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[AnalyticsAggregate]:
        """
        Get count aggregates grouped by dimensions.

        Args:
            dimensions: Fields to group by
            filters: Optional filters to apply
            start_time: Optional start of time range
            end_time: Optional end of time range

        Returns:
            List of analytics aggregates with counts

        Raises:
            Exception: If database operation fails
        """
        # Build the query
        select_columns = []
        group_by_columns = []

        # Add dimension columns
        for dim in dimensions:
            if dim == "date":
                # Extract date part for date dimension
                date_column = func.date(AnalyticsEventModel.timestamp).label("date")
                select_columns.append(date_column)
                group_by_columns.append(date_column)
            else:
                # Use regular column for other dimensions
                column = getattr(AnalyticsEventModel, dim)
                select_columns.append(column)
                group_by_columns.append(column)

        # Add count for the metric
        select_columns.append(func.count().label("count"))

        # Build the query
        stmt = select(*select_columns)

        # Apply filters
        if filters:
            conditions = []
            for field, value in filters.items():
                if hasattr(AnalyticsEventModel, field):
                    column = getattr(AnalyticsEventModel, field)
                    conditions.append(column == value)

            if conditions:
                stmt = stmt.where(and_(*conditions))

        # Apply time range
        if start_time:
            stmt = stmt.where(AnalyticsEventModel.timestamp >= start_time)
        if end_time:
            stmt = stmt.where(AnalyticsEventModel.timestamp <= end_time)

        # Apply grouping
        stmt = stmt.group_by(*group_by_columns)

        # Execute query
        result = await self._session.execute(stmt)
        rows = result.all()

        # Convert to domain entities
        aggregates = []
        for row in rows:
            # Extract dimensions from row
            row_dimensions = {}
            for i, dim in enumerate(dimensions):
                row_dimensions[dim] = row[i]

            # Create aggregate
            aggregates.append(
                AnalyticsAggregate(
                    dimensions=row_dimensions,
                    metrics={"count": row[-1]},  # Last column is the count
                    time_period={"start": start_time, "end": end_time},
                )
            )

        return aggregates

    async def save_aggregate(
        self, aggregate: AnalyticsAggregate, ttl_seconds: int | None = None
    ) -> AnalyticsAggregate:
        """
        Save a pre-computed aggregate for faster retrieval.

        Args:
            aggregate: The analytics aggregate to save
            ttl_seconds: Optional time-to-live in seconds

        Returns:
            The saved aggregate with assigned ID

        Raises:
            Exception: If database operation fails
        """
        try:
            # Convert domain entity to ORM model
            model = AnalyticsAggregateModel(
                dimensions=aggregate.dimensions,
                metrics=aggregate.metrics,
                time_period=aggregate.time_period,
                created_at=datetime.now(UTC),
                ttl=ttl_seconds,
            )

            # Add to session and flush to get ID
            self._session.add(model)
            await self._session.flush()

            # Return domain entity with new ID
            return AnalyticsAggregate(
                dimensions=model.dimensions,
                metrics=model.metrics,
                time_period=model.time_period,
            )

        except SQLAlchemyError as e:
            self._logger.error(f"Error saving analytics aggregate: {e!s}")
            raise
