"""
Database Models for Novamind Digital Twin Backend.

This module contains the SQLAlchemy models for the database.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    String,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base

from app.domain.entities.patient import Patient
from app.domain.value_objects.address import Address
from app.domain.value_objects.emergency_contact import EmergencyContact
from app.infrastructure.persistence.sqlalchemy.types.encrypted_types import (
    EncryptedJSON,
    EncryptedString,
)

Base = declarative_base()


class PatientModel(Base):
    """SQLAlchemy model for Patient with HIPAA-compliant PHI encryption."""

    __tablename__ = "patients"

    # Primary identifiers
    id = Column(UUID, primary_key=True, default=uuid.uuid4)

    # PHI fields - all using encrypted types
    first_name = Column(EncryptedString)
    last_name = Column(EncryptedString)
    full_name = Column(EncryptedString)  # Denormalized for search
    date_of_birth = Column(DateTime)
    gender = Column(String)

    # Contact information - also PHI fields
    email = Column(EncryptedString)
    phone = Column(EncryptedString)
    address = Column(EncryptedJSON)  # Stores the Address value object as JSON

    # Medical identifiers - PHI
    insurance_number = Column(EncryptedString)
    ssn = Column(EncryptedString)
    medical_record_number = Column(EncryptedString)
    emergency_contact = Column(EncryptedJSON)  # Stores EmergencyContact value object
    insurance = Column(EncryptedJSON)

    # Status fields
    active = Column(Boolean, default=True)
    created_by = Column(UUID, ForeignKey("users.id"), nullable=True)

    # Clinical data
    diagnoses = Column(EncryptedJSON)  # List of diagnoses
    medications = Column(EncryptedJSON)  # List of medications
    allergies = Column(EncryptedJSON)  # List of allergies
    medical_history = Column(EncryptedJSON)  # List of medical history items
    treatment_notes = Column(EncryptedJSON)  # List of treatment notes

    # Audit timestamps
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    @classmethod
    def from_domain(cls, patient: Patient) -> "PatientModel":
        """Convert domain Patient entity to PatientModel."""
        address_dict = patient.address.to_dict() if patient.address else None
        emergency_contact_dict = (
            patient.emergency_contact.to_dict() if patient.emergency_contact else None
        )

        return cls(
            id=patient.id,
            first_name=patient.first_name,
            last_name=patient.last_name,
            full_name=patient.name,
            date_of_birth=patient.date_of_birth,
            gender=patient.gender,
            email=patient.email,
            phone=patient.phone,
            address=address_dict,
            insurance_number=patient.insurance_number,
            ssn=patient.ssn,
            medical_record_number=patient.medical_record_number,
            emergency_contact=emergency_contact_dict,
            insurance=patient.insurance,
            active=patient.active,
            created_by=patient.created_by,
            diagnoses=patient.diagnoses,
            medications=patient.medications,
            allergies=patient.allergies,
            medical_history=patient.medical_history,
            treatment_notes=patient.treatment_notes,
            created_at=patient.created_at,
            updated_at=patient.updated_at,
        )

    def to_domain(self) -> Patient:
        """Convert PatientModel to domain Patient entity."""
        address_obj = Address(**self.address) if self.address else None
        emergency_contact_obj = (
            EmergencyContact(**self.emergency_contact) if self.emergency_contact else None
        )

        return Patient(
            id=self.id,
            first_name=self.first_name,
            last_name=self.last_name,
            name=self.full_name,
            date_of_birth=self.date_of_birth,
            gender=self.gender,
            email=self.email,
            phone=self.phone,
            address=address_obj,
            insurance_number=self.insurance_number,
            ssn=self.ssn,
            medical_record_number=self.medical_record_number,
            emergency_contact=emergency_contact_obj,
            insurance=self.insurance,
            active=self.active,
            created_by=self.created_by,
            diagnoses=self.diagnoses or [],
            medications=self.medications or [],
            allergies=self.allergies or [],
            medical_history=self.medical_history or [],
            treatment_notes=self.treatment_notes or [],
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
