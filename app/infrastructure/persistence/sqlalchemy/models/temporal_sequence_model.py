"""
SQLAlchemy models for temporal sequences and events.

This module defines the ORM models for temporal sequences and events,
supporting neural network modeling and temporal analysis.
"""

import sqlalchemy as sa
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.utils.datetime_utils import now_utc
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.types import JSONEncodedDict, GUID


class TemporalSequenceModel(Base):
    """
    Model for storing temporal sequences.
    
    Each record represents a sequence of temporal data points with
    metadata about the sequence structure and features.
    """
    __tablename__ = "temporal_sequences"
    
    # Primary key and relations
    sequence_id = sa.Column(GUID, primary_key=True)
    patient_id = sa.Column(GUID, nullable=True, index=True)
    
    # Sequence metadata
    feature_names = sa.Column(sa.ARRAY(sa.String), nullable=False)
    sequence_metadata = sa.Column(JSONEncodedDict, nullable=False, default={})
    
    # Audit fields
    created_at = sa.Column(sa.DateTime, default=now_utc, nullable=False)
    updated_at = sa.Column(sa.DateTime, default=now_utc, onupdate=now_utc, nullable=False)
    
    # Relationships
    data_points = sa.orm.relationship(
        "TemporalDataPointModel", 
        back_populates="sequence",
        order_by="TemporalDataPointModel.position",
        cascade="all, delete-orphan"
    )
    
    # Indexes for common query patterns
    __table_args__ = (
        sa.Index("idx_temporal_sequences_patient", "patient_id"),
    )


class TemporalDataPointModel(Base):
    """
    Model for storing temporal data points.
    
    Each record represents a single point in a temporal sequence,
    with a position index and associated values.
    """
    __tablename__ = "temporal_data_points"
    
    # Composite primary key
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    sequence_id = sa.Column(GUID, sa.ForeignKey("temporal_sequences.sequence_id"), nullable=False)
    position = sa.Column(sa.Integer, nullable=False)
    
    # Data point values
    timestamp = sa.Column(sa.DateTime, nullable=False)
    values = sa.Column(JSONEncodedDict, nullable=False)
    
    # Relationships
    sequence = sa.orm.relationship("TemporalSequenceModel", back_populates="data_points")
    
    # Indexes for common query patterns
    __table_args__ = (
        sa.Index("idx_temporal_data_points_sequence", "sequence_id", "position"),
        sa.UniqueConstraint("sequence_id", "position", name="uq_temporal_data_points_position")
    )


class EventModel(Base):
    """
    Model for storing correlated events.
    
    Each record represents a single event in an event chain, with
    correlation tracking to connect related events.
    """
    __tablename__ = "temporal_events"
    
    # Primary key and relations
    id = sa.Column(GUID, primary_key=True)
    correlation_id = sa.Column(GUID, nullable=False, index=True)
    parent_event_id = sa.Column(GUID, sa.ForeignKey("temporal_events.id"), nullable=True)
    
    # Patient relation for HIPAA compliance
    patient_id = sa.Column(GUID, nullable=True, index=True)
    
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