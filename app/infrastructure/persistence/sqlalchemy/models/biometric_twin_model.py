"""
SQLAlchemy models for BiometricTwin entities.

This module defines the database models for storing biometric twin data,
including the core twin entity and its associated data points.

IMPORTANT: This module has been refactored to use a clean registry pattern
that prevents SQLAlchemy conflicts during testing.
"""

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    String,
)
from sqlalchemy import UUID as SQLAlchemyUUID
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import relationship

from app.domain.utils.datetime_utils import now_utc

# Import the shared base class to ensure consistent registry
from app.infrastructure.persistence.sqlalchemy.models.base import Base, TimestampMixin


class BiometricTwinModel(Base, TimestampMixin):
    """
    SQLAlchemy model for BiometricTwin entities.

    This model represents the core biometric twin entity in the database,
    storing metadata about the twin and its relationship to a patient.
    """

    __tablename__ = "biometric_twins"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id = Column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("patients.id"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime, nullable=False, default=now_utc)
    updated_at = Column(DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    baseline_established = Column(Boolean, nullable=False, default=False)
    connected_devices = Column(JSON, nullable=True)
    config: Column = Column(MutableDict.as_mutable(JSON), nullable=True)
    status = Column(String(50), default="active", nullable=False)

    patient = relationship("Patient", back_populates="biometric_twin")
    data_points = relationship(
        "app.infrastructure.persistence.sqlalchemy.models.biometric_twin_model.BiometricDataPointModel",
        back_populates="twin",
        cascade="all, delete-orphan",
    )
    timeseries_data = relationship(
        "BiometricTimeseriesDataModel",
        back_populates="biometric_twin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        """String representation of the model."""
        return f"<BiometricTwin(id={self.id}, patient_id={self.patient_id})>"


class BiometricDataPointModel(Base):
    """
    SQLAlchemy model for BiometricDataPoint entities.

    This model represents individual biometric measurements associated with
    a biometric twin, storing the measurement value, metadata, and context.
    """

    __tablename__ = "biometric_data_points"

    data_id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    twin_id = Column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("biometric_twins.id"),
        index=True,
        nullable=False,
    )
    data_type = Column(String(100), index=True, nullable=False)
    value = Column(String, nullable=False)
    value_type = Column(String, nullable=False)  # "number", "string", "json"
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String, nullable=False, index=True)
    metadata_json = Column("metadata", JSON, nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)

    # Define relationship to BiometricTwinModel using string reference
    twin = relationship(
        "app.infrastructure.persistence.sqlalchemy.models.biometric_twin_model.BiometricTwinModel",
        back_populates="data_points",
    )

    def __repr__(self) -> str:
        """String representation of the model."""
        return (
            f"<BiometricDataPoint(data_id={self.data_id}, "
            f"twin_id={self.twin_id}, data_type={self.data_type})>"
        )


class BiometricTimeseriesDataModel(Base, TimestampMixin):
    __tablename__ = "biometric_timeseries_data"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    biometric_twin_id = Column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("biometric_twins.id"),
        nullable=False,
        index=True,
    )
    data_type = Column(String(100), nullable=False, index=True)
    timestamp = Column(DateTime, default=now_utc, nullable=False, index=True)
    value_numeric = Column(Float, nullable=True)
    value_string = Column(String, nullable=True)
    value_json: Column = Column(MutableDict.as_mutable(JSON), nullable=True)
    unit = Column(String(50), nullable=True)
    metadata_: Column = Column("metadata", MutableDict.as_mutable(JSON), nullable=True)

    biometric_twin = relationship("BiometricTwinModel", back_populates="timeseries_data")


# Export the models in a safe way that helps prevent registry conflicts in tests
__all__ = ["BiometricDataPointModel", "BiometricTwinModel"]
