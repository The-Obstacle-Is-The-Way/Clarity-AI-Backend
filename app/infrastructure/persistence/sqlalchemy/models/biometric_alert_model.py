"""
SQLAlchemy model for BiometricAlert entities.

This module defines the database model for storing biometric alerts,
which are generated from biometric data analysis to notify clinical staff
of concerning patterns in patient biometric data.
"""

import uuid
from sqlalchemy import (
    Column,
    ForeignKey,
    String,
    Text,
    JSON,
    Boolean,
    DateTime,
    Enum as SQLAlchemyEnum,
    UUID as SQLAlchemyUUID
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.mutable import MutableDict

from app.domain.utils.datetime_utils import now_utc
# from app.infrastructure.persistence.sqlalchemy.config.database import Base # Old Base
from app.infrastructure.persistence.sqlalchemy.models.base import Base, TimestampMixin, AuditMixin
from app.infrastructure.persistence.sqlalchemy.models.base import Base # Canonical Base
# from app.infrastructure.persistence.sqlalchemy.types import GUID # REMOVED
from app.domain.entities.biometric_alert import AlertStatusEnum 
from app.domain.entities.biometric_alert_rule import AlertPriority as AlertPriorityEnum


class BiometricAlertModel(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for BiometricAlert entities.
    
    This model represents clinical alerts generated from biometric data analysis,
    storing information about the alert, its status, and related clinical context.
    """
    
    __tablename__ = "biometric_alerts"
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("patients.id"), nullable=False, index=True)
    alert_type = Column(String, index=True, nullable=False)
    description = Column(String, nullable=False)
    priority = Column(SQLAlchemyEnum(AlertPriorityEnum), nullable=False)
    rule_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("biometric_rules.id"), nullable=False, index=True)
    status = Column(SQLAlchemyEnum(AlertStatusEnum), default=AlertStatusEnum.NEW, nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=now_utc, index=True)
    updated_at = Column(DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    
    # Acknowledgment and resolution
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by_user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by_user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    resolution_notes = Column(String, nullable=True)
    
    # Additional data
    data_points = Column(JSON, nullable=False)  # Serialized list of data points that triggered the alert
    alert_metadata = Column(JSON, nullable=True)  # Renamed from metadata
    
    triggering_event_details = Column(MutableDict.as_mutable(JSON), nullable=True)
    notes = Column(Text, nullable=True)
    
    patient = relationship("Patient") # Add backref in Patient model if needed
    rule = relationship("BiometricRuleModel") # Add backref in BiometricRuleModel if needed
    acknowledged_by_user = relationship("User", foreign_keys=[acknowledged_by_user_id])
    resolved_by_user = relationship("User", foreign_keys=[resolved_by_user_id])
    
    def __repr__(self) -> str:
        """String representation of the model."""
        return (
            f"<BiometricAlertModel(id={self.id}, "
            f"patient_id={self.patient_id}, "
            f"rule_id={self.rule_id}, "
            f"status={self.status})>"
        )