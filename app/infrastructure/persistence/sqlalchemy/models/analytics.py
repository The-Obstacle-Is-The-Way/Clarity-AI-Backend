"""
SQLAlchemy models for analytics.

This module defines the ORM models for analytics data,
mapping domain entities to database tables.
"""

import datetime
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.domain.utils.datetime_utils import now_utc

# from app.infrastructure.persistence.sqlalchemy.config.base import Base # Old Base
# from app.infrastructure.database.base_class import TimestampMixin # Old TimestampMixin
# Use the canonical Base and TimestampMixin from the models package
from app.infrastructure.persistence.sqlalchemy.models.base import (  # Canonical TimestampMixin
    Base,
    TimestampMixin,
)
from app.infrastructure.persistence.sqlalchemy.types import JSONEncodedDict

# from app.infrastructure.persistence.sqlalchemy.types import GUID # MODIFIED: Comment out GUID


class AnalyticsEventModel(Base, TimestampMixin):
    """
    SQLAlchemy model for analytics events.

    This model stores individual analytics events like page views,
    feature usage, and other trackable user interactions.
    """

    __tablename__ = "analytics_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_data: Mapped[dict] = mapped_column(JSONEncodedDict, nullable=False, default=dict)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True, index=True
    )
    session_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, nullable=False, default=now_utc, index=True
    )
    processed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True, index=True
    )
    correlation_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)

    # Properly configure the relationship with lazy loading
    user = relationship(
        "User",
        back_populates="analytics_events",
        foreign_keys=[user_id],
        lazy="selectin",
    )

    # Useful indexes for analytics queries
    __table_args__ = (
        # Index for filtering by event type and time range
        Index("ix_analytics_events_type_timestamp", "event_type", "timestamp"),
        # Index for user analytics
        Index("ix_analytics_events_user_timestamp", "user_id", "timestamp"),
        # Index for session analytics
        Index("ix_analytics_events_session_timestamp", "session_id", "timestamp"),
    )

    def __repr__(self) -> str:
        """Return string representation of the model."""
        return f"<AnalyticsEvent(id={self.id}, type={self.event_type}, timestamp={self.timestamp})>"


class AnalyticsAggregateModel(Base, TimestampMixin):
    """
    SQLAlchemy model for pre-computed analytics aggregates.

    This model stores aggregated analytics data like counts, averages,
    and other metrics grouped by dimensions for faster dashboard retrieval.
    """

    __tablename__ = "analytics_aggregates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    aggregate_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    dimensions: Mapped[dict] = mapped_column(JSONEncodedDict, nullable=False, default=dict)
    metrics: Mapped[dict] = mapped_column(JSONEncodedDict, nullable=False, default=dict)
    aggregation_metadata: Mapped[dict | None] = mapped_column(JSONEncodedDict, nullable=True)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)  # Time-to-live in seconds

    __table_args__ = (
        # Index for efficient lookups by dimensions
        Index("ix_analytics_aggregates_dimensions", "dimensions"),
        # Index for finding aggregates by type
        Index("ix_analytics_aggregates_type_created", "aggregate_type", "created_at"),
    )

    def __repr__(self) -> str:
        """Return string representation of the model."""
        dim_str = ", ".join(f"{k}={v}" for k, v in self.dimensions.items())
        return f"<AnalyticsAggregate(id={self.id}, dimensions={dim_str})>"


class AnalyticsJobModel(Base, TimestampMixin):
    """
    SQLAlchemy model for analytics processing jobs.

    This model tracks background analytics processing jobs,
    such as batch processing, aggregation, and reporting tasks.
    """

    __tablename__ = "analytics_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    parameters: Mapped[dict] = mapped_column(JSONEncodedDict, nullable=False, default=dict)
    results: Mapped[dict | None] = mapped_column(JSONEncodedDict, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    started_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        """Return string representation of the model."""
        return f"<AnalyticsJob(id={self.id}, type={self.job_type}, status={self.status})>"
