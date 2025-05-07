"""
SQLAlchemy model for Medication entity.

This module defines the SQLAlchemy ORM model for the Medication entity,
mapping the domain entity to the database schema.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, String, Text, UUID as SQLAlchemyUUID
from sqlalchemy.orm import relationship

from app.infrastructure.persistence.sqlalchemy.models.base import Base, TimestampMixin, AuditMixin


class MedicationModel(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for the Medication entity.

    This model maps to the 'medications' table in the database and
    represents medications prescribed to patients by providers.
    """

    __tablename__ = "medications"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("patients.id"), nullable=False)
    provider_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("providers.id"), nullable=False)
    name = Column(String(255), nullable=False, index=True)
    dosage = Column(String(100), nullable=False)
    frequency = Column(String(100), nullable=False)
    start_date = Column(Date, nullable=False)
    end_date = Column(Date, nullable=True)
    instructions = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=datetime.now,
        onupdate=datetime.now,
        nullable=False,
    )

    # Relationships with correct model references
    patient = relationship("Patient", back_populates="medication_records")
    provider = relationship("ProviderModel", back_populates="medications")

    def __repr__(self) -> str:
        """Return string representation of the medication."""
        return f"<Medication(id={self.id}, name={self.name}, patient_id={self.patient_id})>"

    @classmethod
    def from_domain(cls, medication) -> "MedicationModel":
        """
        Create a SQLAlchemy model instance from a domain entity.

        Args:
            medication: Domain Medication entity

        Returns:
            MedicationModel: SQLAlchemy model instance
        """
        return cls(
            id=medication.id,
            patient_id=medication.patient_id,
            provider_id=medication.provider_id,
            name=medication.name,
            dosage=(
                medication.dosage.value
                if hasattr(medication.dosage, "value")
                else medication.dosage
            ),
            frequency=medication.frequency,
            start_date=medication.start_date,
            end_date=medication.end_date,
            instructions=medication.instructions,
            active=medication.active,
        )

    def to_domain(self):
        """
        Convert SQLAlchemy model instance to domain entity.

        Returns:
            Medication: Domain entity instance
        """
        from app.domain.entities.medication import Medication
        from app.domain.value_objects.medication_dosage import MedicationDosage

        # Try to convert dosage string to MedicationDosage value object if possible
        try:
            dosage = MedicationDosage.from_string(self.dosage)
        except (ValueError, AttributeError):
            dosage = self.dosage

        return Medication(
            id=self.id,
            patient_id=self.patient_id,
            provider_id=self.provider_id,
            name=self.name,
            dosage=dosage,
            frequency=self.frequency,
            start_date=self.start_date,
            end_date=self.end_date,
            instructions=self.instructions,
            active=self.active,
        )

class PatientMedicationModel(Base, TimestampMixin, AuditMixin):
    __tablename__ = "patient_medications"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("patients.id"), nullable=False, index=True)
    medication_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("medications.id"), nullable=False, index=True)
    # ... other fields ...
