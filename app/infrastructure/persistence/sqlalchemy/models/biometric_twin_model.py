"""
SQLAlchemy models for BiometricTwin entities.

This module defines the database models for storing biometric twin data,
including the core twin entity and its associated data points.

IMPORTANT: This module has been refactored to use a clean registry pattern
that prevents SQLAlchemy conflicts during testing.
"""

import uuid

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import relationship

from app.domain.utils.datetime_utils import now_utc

# Import the shared base class to ensure consistent registry
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.types import GUID


class BiometricTwinModel(Base):
    """
    SQLAlchemy model for BiometricTwin entities.
    
    This model represents the core biometric twin entity in the database,
    storing metadata about the twin and its relationship to a patient.
    """
    
    __tablename__ = "biometric_twins"
    
    twin_id = Column(GUID, primary_key=True, default=uuid.uuid4)
    patient_id = Column(GUID, index=True, nullable=False)
    created_at = Column(DateTime, nullable=False, default=now_utc)
    updated_at = Column(DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    baseline_established = Column(Boolean, nullable=False, default=False)
    connected_devices = Column(JSON, nullable=True)
    
    # Define the relationship to data points - use string reference to avoid circular imports
    # This will be properly mapped when both classes are loaded
    data_points = relationship(
        "app.infrastructure.persistence.sqlalchemy.models.biometric_twin_model.BiometricDataPointModel", 
        back_populates="twin",
        cascade="all, delete-orphan"
    )
    
    def __repr__(self) -> str:
        """String representation of the model."""
        return f"<BiometricTwin(twin_id={self.twin_id}, patient_id={self.patient_id})>"


class BiometricDataPointModel(Base):
    """
    SQLAlchemy model for BiometricDataPoint entities.
    
    This model represents individual biometric measurements associated with
    a biometric twin, storing the measurement value, metadata, and context.
    """
    
    __tablename__ = "biometric_data_points"
    
    data_id = Column(GUID, primary_key=True, default=uuid.uuid4)
    twin_id = Column(GUID, ForeignKey("biometric_twins.twin_id"), index=True, nullable=False)
    data_type = Column(String, index=True, nullable=False)
    value = Column(String, nullable=False)
    value_type = Column(String, nullable=False)  # "number", "string", "json"
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String, nullable=False, index=True)
    metadata_json = Column("metadata", JSON, nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    
    # Define relationship to BiometricTwinModel using string reference
    twin = relationship("app.infrastructure.persistence.sqlalchemy.models.biometric_twin_model.BiometricTwinModel", back_populates="data_points")
    
    def __repr__(self) -> str:
        """String representation of the model."""
        return (
            f"<BiometricDataPoint(data_id={self.data_id}, "
            f"twin_id={self.twin_id}, data_type={self.data_type})>"
        )


# Export the models in a safe way that helps prevent registry conflicts in tests
__all__ = ['BiometricDataPointModel', 'BiometricTwinModel']