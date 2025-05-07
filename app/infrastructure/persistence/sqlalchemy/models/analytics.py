"""
SQLAlchemy models for analytics.

This module defines the ORM models for analytics data,
mapping domain entities to database tables.
"""

import uuid

from sqlalchemy import JSON, Column, DateTime, Index, Integer, String, ForeignKey, UUID as SQLAlchemyUUID
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import relationship

from app.domain.utils.datetime_utils import now_utc
# from app.infrastructure.persistence.sqlalchemy.config.base import Base # Old Base
# from app.infrastructure.database.base_class import TimestampMixin # Old TimestampMixin

# Use the canonical Base and TimestampMixin from the models package
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.models.base import TimestampMixin # Canonical TimestampMixin
# from app.infrastructure.persistence.sqlalchemy.types import GUID # MODIFIED: Comment out GUID


class AnalyticsEventModel(Base, TimestampMixin):
    """
    SQLAlchemy model for analytics events.
    
    This model stores individual analytics events like page views,
    feature usage, and other trackable user interactions.
    """
    
    __tablename__ = "analytics_events"
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(100), nullable=False, index=True)
    event_data = Column(MutableDict.as_mutable(JSON), nullable=False, default=dict)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    session_id = Column(String(100), nullable=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=now_utc, index=True)
    processed_at = Column(DateTime, nullable=True, index=True)
    correlation_id = Column(String(100), nullable=True, index=True)
    
    # Define the relationship to the User model
    user = relationship("User", back_populates="analytics_events")
    
    # Useful indexes for analytics queries
    __table_args__ = (
        # Index for filtering by event type and time range
        Index('ix_analytics_events_type_timestamp', 'event_type', 'timestamp'),
        
        # Index for user analytics
        Index('ix_analytics_events_user_timestamp', 'user_id', 'timestamp'),
        
        # Index for session analytics
        Index('ix_analytics_events_session_timestamp', 'session_id', 'timestamp'),
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
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    aggregate_type = Column(String(50), nullable=False, index=True)
    dimensions = Column(MutableDict.as_mutable(JSON), nullable=False, default=dict)
    metrics = Column(MutableDict.as_mutable(JSON), nullable=False, default=dict)
    aggregation_metadata = Column(MutableDict.as_mutable(JSON), nullable=True)
    ttl = Column(Integer, nullable=True)  # Time-to-live in seconds
    
    __table_args__ = (
        # Index for efficient lookups by dimensions
        Index('ix_analytics_aggregates_dimensions', 'dimensions'),
        
        # Index for finding aggregates by type
        Index('ix_analytics_aggregates_type_created', 'aggregate_type', 'created_at'),
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
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_type = Column(String(50), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="pending", index=True)
    parameters = Column(MutableDict.as_mutable(JSON), nullable=False, default=dict)
    results = Column(MutableDict.as_mutable(JSON), nullable=True)
    error = Column(String(500), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    def __repr__(self) -> str:
        """Return string representation of the model."""
        return f"<AnalyticsJob(id={self.id}, type={self.job_type}, status={self.status})>"