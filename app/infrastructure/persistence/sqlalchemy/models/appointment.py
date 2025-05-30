"""
SQLAlchemy model for Appointment entity.

This module defines the SQLAlchemy ORM model for the Appointment entity,
mapping the domain entity to the database schema.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy import Enum as SQLAlchemyEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.domain.entities.appointment import AppointmentStatus
from app.infrastructure.persistence.sqlalchemy.models.base import (
    AuditMixin,
    Base,
    TimestampMixin,
)
from app.infrastructure.persistence.sqlalchemy.types import GUID

if TYPE_CHECKING:
    from app.domain.entities.appointment import Appointment


class AppointmentModel(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for the Appointment entity.

    This model maps to the 'appointments' table in the database and
    represents scheduled meetings between providers and patients.
    """

    __tablename__ = "appointments"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    patient_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("patients.id"),
        nullable=False,
        index=True,
    )
    provider_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("providers.id"),
        nullable=False,
        index=True,
    )
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        nullable=False
    )
    end_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        nullable=False
    )
    appointment_type: Mapped[str] = mapped_column(
        String(50), 
        nullable=False
    )
    status: Mapped[AppointmentStatus] = mapped_column(
        SQLAlchemyEnum(AppointmentStatus), 
        nullable=False
    )
    notes: Mapped[str | None] = mapped_column(
        Text, 
        nullable=True
    )
    location: Mapped[str | None] = mapped_column(
        String(255), 
        nullable=True
    )

    # Note: created_at and updated_at are provided by TimestampMixin
    # Removed duplicate definitions to avoid conflicts

    # Relationships - aligned to match the actual database schema and foreign keys
    patient = relationship("Patient", back_populates="appointments")
    provider = relationship("ProviderModel", back_populates="appointments")
    clinical_notes = relationship(
        "ClinicalNoteModel", back_populates="appointment", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        """Return string representation of the appointment."""
        return f"<Appointment(id={self.id}, patient_id={self.patient_id}, start_time={self.start_time})>"

    @classmethod
    def from_domain(cls, appointment: "Appointment") -> "AppointmentModel":
        """
        Create a SQLAlchemy model instance from a domain entity.

        Args:
            appointment: Domain Appointment entity

        Returns:
            AppointmentModel: SQLAlchemy model instance
        """
        return cls(
            id=appointment.id,
            patient_id=appointment.patient_id,
            provider_id=appointment.provider_id,
            start_time=appointment.start_time,
            end_time=appointment.end_time,
            appointment_type=appointment.appointment_type.value,
            status=appointment.status.value,
            notes=appointment.notes,
            location=appointment.location,
        )

    def to_domain(self) -> "Appointment":
        """
        Convert SQLAlchemy model instance to domain entity.

        Returns:
            Appointment: Domain entity instance
        """
        from app.domain.entities.appointment import (
            Appointment,
            AppointmentStatus,
            AppointmentType,
        )

        return Appointment(
            id=self.id,
            patient_id=self.patient_id,
            provider_id=self.provider_id,
            start_time=self.start_time,
            end_time=self.end_time,
            appointment_type=AppointmentType(self.appointment_type),
            status=AppointmentStatus(self.status),
            notes=self.notes,
            location=self.location,
        )
