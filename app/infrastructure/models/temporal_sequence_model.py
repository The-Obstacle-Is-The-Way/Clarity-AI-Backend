"""
SQLAlchemy models for temporal sequence persistence.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base

from app.domain.utils.datetime_utils import now_utc
from app.infrastructure.persistence.sqlalchemy.types import (
    FloatListDecorator,
    JSONEncodedDict,
    StringListDecorator,
)

# Create a properly typed declarative base for mypy
BaseType = declarative_base()


# This class provides proper typing for SQLAlchemy models
class Base(BaseType):  # type: ignore
    __abstract__ = True


class TemporalSequenceModel(Base):
    """
    Model for storing temporal sequence metadata.

    This model stores the metadata for a temporal sequence without the actual
    data points, which are stored in TemporalDataPointModel for efficiency.
    """

    __tablename__ = "temporal_sequences"

    # Primary key and relations
    sequence_id = sa.Column(UUID, primary_key=True)
    patient_id = sa.Column(UUID, nullable=False, index=True)

    # Sequence metadata
    feature_names = sa.Column(StringListDecorator, nullable=False)
    sequence_metadata = sa.Column(JSONEncodedDict, nullable=False, default={})

    # Audit fields
    created_at = sa.Column(sa.DateTime, default=now_utc, nullable=False)
    updated_at = sa.Column(sa.DateTime, default=now_utc, onupdate=now_utc, nullable=False)
    created_by = sa.Column(UUID, nullable=True)

    # HIPAA compliance - audit logging
    access_count = sa.Column(sa.Integer, default=0, nullable=False)
    last_accessed_at = sa.Column(sa.DateTime, nullable=True)
    last_accessed_by = sa.Column(UUID, nullable=True)

    __table_args__ = (
        sa.Index(
            "idx_temporal_sequences_patient_feature",
            "patient_id",
            sa.text("feature_names"),
        ),
    )


class TemporalDataPointModel(Base):
    """
    Model for storing individual data points in a temporal sequence.

    Each record represents a single time point in a sequence, with an array of
    values corresponding to the feature names in the parent sequence.
    """

    __tablename__ = "temporal_data_points"

    # Composite primary key
    sequence_id = sa.Column(UUID, sa.ForeignKey("temporal_sequences.sequence_id"), primary_key=True)
    position = sa.Column(sa.Integer, primary_key=True)

    # Time point data
    timestamp = sa.Column(sa.DateTime, nullable=False)
    values = sa.Column(FloatListDecorator, nullable=False)

    # Allow indexing by timestamp for time-based queries
    __table_args__ = (sa.Index("idx_temporal_data_points_timestamp", "sequence_id", "timestamp"),)


class EventModel(Base):
    """
    Model for storing correlated events.

    Each record represents a single event in an event chain, with
    correlation tracking to connect related events.
    """

    __tablename__ = "temporal_events"

    # Primary key and relations
    id = sa.Column(UUID, primary_key=True)
    correlation_id = sa.Column(UUID, nullable=False, index=True)
    parent_event_id = sa.Column(UUID, sa.ForeignKey("temporal_events.id"), nullable=True)

    # Patient relation for HIPAA compliance
    patient_id = sa.Column(UUID, nullable=True, index=True)

    # Event data
    event_type = sa.Column(sa.String, nullable=False, index=True)
    timestamp = sa.Column(sa.DateTime, nullable=False, index=True)
    event_metadata = sa.Column(JSONEncodedDict, nullable=False, default={})

    # Audit fields
    created_at = sa.Column(sa.DateTime, default=now_utc, nullable=False)

    # Indexes for common query patterns
    __table_args__ = (
        sa.Index("idx_temporal_events_correlation", "correlation_id", "timestamp"),
        sa.Index("idx_temporal_events_patient_type", "patient_id", "event_type"),
    )
