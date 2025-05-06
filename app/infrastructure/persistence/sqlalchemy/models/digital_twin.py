"""
SQLAlchemy models for digital twin entities.

This module defines the ORM models for storing digital twin data in the database,
providing mapping between domain entities and the database schema.
"""

import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship

from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.types import GUID


class BiometricDataPointModel(Base):
    """
    SQLAlchemy model for biometric data points.
    
    This represents a single measurement of a biometric value at a specific point in time.
    """
    
    __tablename__ = "biometric_data_points"
    __table_args__ = {'extend_existing': True}
    
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    timeseries_id = Column(GUID, ForeignKey("biometric_timeseries.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    value_json = Column(Text, nullable=False)
    source = Column(String(50), nullable=False)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    
    # Relationships
    timeseries = relationship("BiometricTimeseriesModel", back_populates="data_points")
    
    @hybrid_property
    def value(self) -> Any:
        """Get the value, deserializing from JSON if needed."""
        return json.loads(self.value_json)
    
    @value.setter
    def value(self, value: Any) -> None:
        """Set the value, serializing to JSON."""
        self.value_json = json.dumps(value)
    
    @hybrid_property
    def metadata_dict(self) -> dict[str, Any]:
        """Get the metadata as a dictionary."""
        if self.metadata_json:
            return json.loads(self.metadata_json)
        return {}
    
    @metadata_dict.setter
    def metadata_dict(self, metadata: dict[str, Any]) -> None:
        """Set the metadata, serializing to JSON."""
        if metadata:
            self.metadata_json = json.dumps(metadata)
        else:
            self.metadata_json = None


class BiometricTimeseriesModel(Base):
    """
    SQLAlchemy model for biometric timeseries.
    
    This represents a collection of biometric data points of a specific type.
    """
    
    __tablename__ = "biometric_timeseries"
    
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    twin_id = Column(GUID, ForeignKey("digital_twins.id"), nullable=False)
    biometric_type = Column(String(50), nullable=False)
    unit = Column(String(20), nullable=False)
    physiological_range_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    
    # Relationships
    twin = relationship("DigitalTwinModel", back_populates="timeseries")
    data_points = relationship("BiometricDataPointModel", back_populates="timeseries", cascade="all, delete-orphan")
    
    @hybrid_property
    def physiological_range(self) -> dict[str, float] | None:
        """Get the physiological range as a dictionary."""
        if self.physiological_range_json:
            return json.loads(self.physiological_range_json)
        return None
    
    @physiological_range.setter
    def physiological_range(self, range_data: dict[str, float] | None) -> None:
        """Set the physiological range, serializing to JSON."""
        if range_data:
            self.physiological_range_json = json.dumps(range_data)
        else:
            self.physiological_range_json = None


class DigitalTwinModel(Base):
    """
    SQLAlchemy model for digital twins.
    
    This is the aggregate root representing a patient's complete biometric profile.
    """
    
    __tablename__ = "digital_twins"
    
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    patient_id = Column(GUID, nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    version = Column(Integer, default=1, nullable=False)
    configuration_json = Column(JSON, nullable=True)
    state_json = Column(JSON, nullable=True)
    
    # Relationships
    timeseries = relationship("BiometricTimeseriesModel", back_populates="twin", cascade="all, delete-orphan")
