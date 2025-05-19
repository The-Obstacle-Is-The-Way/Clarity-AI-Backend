"""
SQLAlchemy model for ClinicalNote entity.

This module defines the SQLAlchemy ORM model for the ClinicalNote entity,
mapping the domain entity to the database schema.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    UUID as SQLAlchemyUUID,
)
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import relationship

from app.infrastructure.persistence.sqlalchemy.models.base import (
    AuditMixin,
    Base,
    TimestampMixin,
)

if TYPE_CHECKING:
    from app.domain.entities.clinical_note import ClinicalNote


class ClinicalNoteModel(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for the ClinicalNote entity.

    This model maps to the 'clinical_notes' table in the database and
    represents clinical documentation created by providers for patients.
    """

    __tablename__ = "clinical_notes"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id = Column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("patients.id"),
        nullable=False,
        index=True,
    )
    provider_id = Column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("providers.id"),
        nullable=False,
        index=True,
    )
    appointment_id = Column(
        SQLAlchemyUUID(as_uuid=True), ForeignKey("appointments.id"), nullable=True
    )
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    redacted_content = Column(Text, nullable=True)
    note_type = Column(String(50), nullable=True)
    tags = Column(MutableDict.as_mutable(JSON), nullable=True)
    version = Column(Integer, default=1, nullable=False)
    parent_note_id = Column(
        SQLAlchemyUUID(as_uuid=True), ForeignKey("clinical_notes.id"), nullable=True
    )

    # Relationships with correct model references
    patient = relationship("Patient", back_populates="clinical_notes")
    provider = relationship(
        "ProviderModel", foreign_keys=[provider_id], back_populates="clinical_notes"
    )
    appointment = relationship("AppointmentModel", back_populates="clinical_notes")
    parent_note = relationship("ClinicalNoteModel", remote_side=[id], backref="revisions")

    def __repr__(self) -> str:
        """Return string representation of the clinical note."""
        return f"<ClinicalNote(id={self.id}, patient_id={self.patient_id}, note_type={self.note_type})>"

    @classmethod
    def from_domain(cls, clinical_note: "ClinicalNote") -> "ClinicalNoteModel":
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
            note_type=clinical_note.note_type.value if clinical_note.note_type else None,
            content=clinical_note.content,
            redacted_content=clinical_note.redacted_content,
            title=clinical_note.title,
            tags=clinical_note.tags,
            version=clinical_note.version,
            parent_note_id=clinical_note.parent_note_id,
        )

    def to_domain(self) -> "ClinicalNote":
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
            note_type=NoteType(self.note_type) if self.note_type else None,
            content=self.content,
            redacted_content=self.redacted_content,
            title=self.title,
            tags=self.tags,
            version=self.version,
            parent_note_id=self.parent_note_id,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
