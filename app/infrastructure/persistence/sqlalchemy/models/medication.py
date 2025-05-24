"""
SQLAlchemy model for Medication entity.

This module defines the SQLAlchemy ORM model for the Medication entity,
mapping the domain entity to the database schema.
"""

import uuid
import datetime

from sqlalchemy import UUID as SQLAlchemyUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import (
    Boolean,
    Column,
    Date,
    ForeignKey,
    String,
    Text,
)


from app.infrastructure.persistence.sqlalchemy.models.base import (
    AuditMixin,
    Base,
    TimestampMixin,
)


class MedicationModel(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for the Medication catalog.

    This model maps to the 'medications' table in the database and
    represents general information about medications.
    """

    __tablename__ = "medications"

    id: Mapped[uuid.UUID] = mapped_column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    form: Mapped[str | None] = mapped_column(String(100), nullable=True)  # e.g., tablet, capsule, liquid
    strength: Mapped[str | None] = mapped_column(String(100), nullable=True)  # e.g., 10mg, 50mg/mL
    # manufacturer = Column(String(255), nullable=True) # Optional

    # Relationship to the association table
    prescriptions = relationship("PatientMedicationModel", back_populates="medication_catalog_item")

    def __repr__(self) -> str:
        return f"<MedicationModel(id={self.id}, name='{self.name}')>"


class PatientMedicationModel(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for patient-specific medication prescriptions (association table).

    Links a Patient to a Medication from the catalog and stores prescription details.
    """

    __tablename__ = "patient_medications"

    id: Mapped[uuid.UUID] = mapped_column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id: Mapped[uuid.UUID] = mapped_column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("patients.id"),
        nullable=False,
        index=True,
    )
    medication_id: Mapped[uuid.UUID] = mapped_column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("medications.id"),
        nullable=False,
        index=True,
    )
    provider_id: Mapped[uuid.UUID] = mapped_column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("providers.id"),
        nullable=False,
        index=True,
    )  # MODIFIED: Changed from users.id to providers.id

    # Prescription-specific details
    dosage: Mapped[str] = mapped_column(String(100), nullable=False)
    frequency: Mapped[str] = mapped_column(String(100), nullable=False)
    start_date: Mapped[datetime.date] = mapped_column(Date, nullable=False)
    end_date: Mapped[datetime.date | None] = mapped_column(Date, nullable=True)
    instructions: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )  # Renamed from 'active' to avoid conflict

    # Relationships
    patient = relationship("Patient", back_populates="prescriptions")
    medication_catalog_item = relationship("MedicationModel", back_populates="prescriptions")
    prescribing_provider = relationship(
        "ProviderModel", foreign_keys=[provider_id], back_populates="prescriptions_made"
    )  # MODIFIED: Point to ProviderModel, add back_populates

    def __repr__(self) -> str:
        return f"<PatientMedicationModel(id={self.id}, patient_id={self.patient_id}, medication_id={self.medication_id})>"
