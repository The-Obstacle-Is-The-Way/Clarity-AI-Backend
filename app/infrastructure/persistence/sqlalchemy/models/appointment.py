# -*- coding: utf-8 -*-
"""
SQLAlchemy model for Appointment entity.

This module defines the SQLAlchemy ORM model for the Appointment entity,
mapping the domain entity to the database schema.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.infrastructure.persistence.sqlalchemy.models.base import Base





class AppointmentModel(Base):
    """
    SQLAlchemy model for the Appointment entity.

    This model maps to the 'appointments' table in the database and
    represents scheduled meetings between providers and patients.
    """

    __tablename__ = "appointments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id = Column(UUID(as_uuid=True), ForeignKey("patients.id"), nullable=False)
    provider_id = Column(UUID(as_uuid=True), ForeignKey("providers.id"), nullable=False)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=False)
    appointment_type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False)
    notes = Column(Text, nullable=True)
    virtual = Column(Boolean, default=False, nullable=False)
    location = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=datetime.now,
        onupdate=datetime.now,
        nullable=False,
    )

    # Relationships - aligned to match the actual database schema and foreign keys
    patient = relationship("Patient", back_populates="appointments", foreign_keys=[patient_id])
    provider = relationship("ProviderModel", back_populates="appointments", foreign_keys=[provider_id])
    clinical_notes = relationship("ClinicalNoteModel", back_populates="appointment", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        """Return string representation of the appointment."""
        return f"<Appointment(id={self.id}, patient_id={self.patient_id}, start_time={self.start_time})>"

    @classmethod
    def from_domain(cls, appointment) -> "AppointmentModel":
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
            virtual=appointment.virtual,
            location=appointment.location,
        )

    def to_domain(self):
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
            virtual=self.virtual,
            location=self.location,
        )
