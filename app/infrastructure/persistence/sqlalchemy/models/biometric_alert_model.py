"""
SQLAlchemy model for BiometricAlert entities.

This module defines the database model for storing biometric alerts,
which are generated from biometric data analysis to notify clinical staff
of concerning patterns in patient biometric data.
"""

import uuid
import datetime

from sqlalchemy import (
    JSON,

    DateTime,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy import UUID as SQLAlchemyUUID
from sqlalchemy import Enum as SQLAlchemyEnum
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.domain.entities.biometric_alert import AlertStatusEnum
from app.domain.entities.biometric_alert_rule import AlertPriority as AlertPriorityEnum
from app.domain.utils.datetime_utils import now_utc
from app.infrastructure.persistence.sqlalchemy.models.base import (
    AuditMixin,
    Base,
    TimestampMixin,
)


class BiometricAlertModel(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for BiometricAlert entities.

    This model represents clinical alerts generated from biometric data analysis,
    storing information about the alert, its status, and related clinical context.
    """

    __tablename__ = "biometric_alerts"

    id: Mapped[uuid.UUID] = mapped_column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id: Mapped[uuid.UUID] = mapped_column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("patients.id"),
        nullable=False,
        index=True,
    )
    alert_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    priority: Mapped[AlertPriorityEnum] = mapped_column(SQLAlchemyEnum(AlertPriorityEnum), nullable=False)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("biometric_rules.id"),
        nullable=False,
        index=True,
    )
    status: Mapped[AlertStatusEnum] = mapped_column(
        SQLAlchemyEnum(AlertStatusEnum),
        default=AlertStatusEnum.NEW,
        nullable=False,
        index=True,
    )

    # Timestamps
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False, default=now_utc, index=True)
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Acknowledgment and resolution
    acknowledged_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    resolved_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    resolution_notes: Mapped[str | None] = mapped_column(String, nullable=True)

    # Additional data
    data_points: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )  # Serialized list of data points that triggered the alert
    alert_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # Renamed from metadata

    triggering_event_details: Mapped[dict | None] = mapped_column(MutableDict.as_mutable(JSON), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    patient = relationship("Patient")  # Add backref in Patient model if needed
    rule = relationship("BiometricRuleModel")  # Add backref in BiometricRuleModel if needed
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
