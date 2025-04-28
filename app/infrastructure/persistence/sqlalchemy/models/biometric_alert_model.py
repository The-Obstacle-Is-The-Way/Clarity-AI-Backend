# -*- coding: utf-8 -*-
"""
SQLAlchemy model for BiometricAlert entities.

This module defines the database model for storing biometric alerts,
which are generated from biometric data analysis to notify clinical staff
of concerning patterns in patient biometric data.
"""

from datetime import datetime
from app.domain.utils.datetime_utils import UTC, now_utc
from sqlalchemy import Column, String, DateTime, Float, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship

from app.domain.services.biometric_event_processor import AlertPriority, AlertStatus
from app.infrastructure.persistence.sqlalchemy.config.database import Base


class BiometricAlertModel(Base):
    """
    SQLAlchemy model for BiometricAlert entities.
    
    This model represents clinical alerts generated from biometric data analysis,
    storing information about the alert, its status, and related clinical context.
    """
    
    __tablename__ = "biometric_alerts"
    
    alert_id = Column(String, primary_key=True, index=True)
    patient_id = Column(String, index=True, nullable=False)
    alert_type = Column(String, index=True, nullable=False)
    description = Column(String, nullable=False)
    priority = Column(Enum(AlertPriority), nullable=False, index=True)
    rule_id = Column(String, index=True, nullable=False)
    status = Column(Enum(AlertStatus), nullable=False, default=AlertStatus.NEW, index=True)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=now_utc, index=True)
    updated_at = Column(DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    
    # Acknowledgment and resolution
    acknowledged_by = Column(String, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_by = Column(String, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(String, nullable=True)
    
    # Additional data
    data_points = Column(JSON, nullable=False)  # Serialized list of data points that triggered the alert
    alert_metadata = Column(JSON, nullable=True)  # Renamed from metadata
    
    def __repr__(self) -> str:
        """String representation of the model."""
        return (
            f"<BiometricAlert(alert_id={self.alert_id}, "
            f"patient_id={self.patient_id}, "
            f"alert_type={self.alert_type}, "
            f"priority={self.priority}, "
            f"status={self.status})>"
        )