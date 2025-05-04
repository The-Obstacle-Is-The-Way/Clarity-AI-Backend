"""
SQLAlchemy model for ClinicalNote entity.

This module defines the SQLAlchemy ORM model for the ClinicalNote entity,
mapping the domain entity to the database schema.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.types import GUID


class ClinicalNoteModel(Base):
    """
    SQLAlchemy model for the ClinicalNote entity.

    This model maps to the 'clinical_notes' table in the database and
    represents clinical documentation created by providers for patients.
    """

    __tablename__ = "clinical_notes"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    patient_id = Column(GUID, ForeignKey("patients.id"), nullable=False)
    provider_id = Column(GUID, ForeignKey("providers.id"), nullable=False)
    appointment_id = Column(
        GUID, ForeignKey("appointments.id"), nullable=True
    )
    note_type = Column(String(50), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=datetime.now,
        onupdate=datetime.now,
        nullable=False,
    )
    version = Column(Integer, default=1, nullable=False)

    # Relationships with correct model references
    patient = relationship("Patient", back_populates="clinical_notes")
    provider = relationship("ProviderModel", back_populates="clinical_notes")
    appointment = relationship("AppointmentModel", back_populates="clinical_notes")

    def __repr__(self) -> str:
        """Return string representation of the clinical note."""
        return f"<ClinicalNote(id={self.id}, patient_id={self.patient_id}, note_type={self.note_type})>"

    @classmethod
    def from_domain(cls, clinical_note) -> "ClinicalNoteModel":
        """
        Create a SQLAlchemy model instance from a domain entity.

        Args:
            clinical_note: Domain ClinicalNote entity

        Returns:
            ClinicalNoteModel: SQLAlchemy model instance
        """
        return cls(
            id=clinical_note.id,
            patient_id=clinical_note.patient_id,
            provider_id=clinical_note.provider_id,
            appointment_id=clinical_note.appointment_id,
            note_type=clinical_note.note_type.value,
            content=clinical_note.content,
            version=clinical_note.version,
        )

    def to_domain(self):
        """
        Convert SQLAlchemy model instance to domain entity.

        Returns:
            ClinicalNote: Domain entity instance
        """
        from app.domain.entities.clinical_note import ClinicalNote, NoteType

        return ClinicalNote(
            id=self.id,
            patient_id=self.patient_id,
            provider_id=self.provider_id,
            appointment_id=self.appointment_id,
            note_type=NoteType(self.note_type),
            content=self.content,
            version=self.version,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
