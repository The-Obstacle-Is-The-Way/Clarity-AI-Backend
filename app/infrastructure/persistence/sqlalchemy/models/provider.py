"""
SQLAlchemy model for Provider entity.

This module defines the SQLAlchemy ORM model for the Provider entity,
mapping the domain entity to the database schema following clean architecture principles.
"""

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.persistence.sqlalchemy.models.base import (
    AuditMixin,
    Base,
    TimestampMixin,
)
from app.infrastructure.persistence.sqlalchemy.registry import register_model

# Type-checking only imports to avoid circular imports
if TYPE_CHECKING:
    from app.domain.entities.provider import Provider as DomainProvider


@register_model
class ProviderModel(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for the Provider entity.

    This model maps to the 'providers' table in the database and
    represents healthcare providers in the NOVAMIND system.
    """

    __tablename__ = "providers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # Maps to ProviderType enum
    specialties: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )  # Array of specialties
    license_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    npi_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    address: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # Address as JSON
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    education: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )  # Education history
    certifications: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )  # Certifications
    languages: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )  # Languages spoken
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active"
    )  # Maps to ProviderStatus enum
    availability: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # Availability schedule
    max_patients: Mapped[str | None] = mapped_column(String(10), nullable=True)  # Maximum patients
    current_patient_count: Mapped[str] = mapped_column(String(10), nullable=False, default="0")
    model_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # Additional metadata

    # Relationships
    appointments = relationship(
        "AppointmentModel", back_populates="provider", cascade="all, delete-orphan"
    )
    clinical_notes = relationship(
        "ClinicalNoteModel", back_populates="provider", cascade="all, delete-orphan"
    )
    prescriptions_made = relationship(
        "PatientMedicationModel",
        back_populates="prescribing_provider",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        """Return string representation of the provider."""
        return f"<ProviderModel(id={self.id}, name={self.first_name} {self.last_name}, type={self.provider_type})>"

    @classmethod
    def from_domain(cls, provider: "DomainProvider") -> "ProviderModel":
        """
        Create a Provider model from domain entity.

        Args:
            provider: Domain provider entity

        Returns:
            ProviderModel instance
        """
        return cls(
            id=provider.id if isinstance(provider.id, uuid.UUID) else uuid.UUID(str(provider.id)),
            first_name=provider.first_name,
            last_name=provider.last_name,
            provider_type=provider.provider_type.value if provider.provider_type else None,
            specialties=provider.specialties or [],
            license_number=provider.license_number,
            npi_number=provider.npi_number,
            email=provider.email,
            phone=provider.phone,
            address=provider.address or {},
            bio=provider.bio,
            education=provider.education or [],
            certifications=provider.certifications or [],
            languages=provider.languages or [],
            status=provider.status.value if provider.status else "active",
            availability=provider.availability or {},
            max_patients=str(provider.max_patients) if provider.max_patients is not None else None,
            current_patient_count=str(provider.current_patient_count),
            model_metadata=provider.metadata or {},
            created_at=provider.created_at,
            updated_at=provider.updated_at,
        )

    def to_domain(self) -> "DomainProvider":
        """
        Convert SQLAlchemy model instance to domain entity.

        Returns:
            DomainProvider: Domain entity instance
        """
        from app.domain.entities.provider import Provider, ProviderStatus, ProviderType

        # Convert string enums back to enum instances
        provider_type = None
        if self.provider_type:
            try:
                provider_type = ProviderType(self.provider_type)
            except ValueError:
                provider_type = None

        status = ProviderStatus.ACTIVE
        if self.status:
            try:
                status = ProviderStatus(self.status)
            except ValueError:
                status = ProviderStatus.ACTIVE

        # Convert string numbers back to integers
        max_patients = None
        if self.max_patients:
            try:
                max_patients = int(self.max_patients)
            except (ValueError, TypeError):
                max_patients = None

        current_patient_count = 0
        if self.current_patient_count:
            try:
                current_patient_count = int(self.current_patient_count)
            except (ValueError, TypeError):
                current_patient_count = 0

        return Provider(
            id=self.id,
            first_name=self.first_name,
            last_name=self.last_name,
            provider_type=provider_type,
            specialties=self.specialties or [],
            license_number=self.license_number,
            npi_number=self.npi_number,
            email=self.email,
            phone=self.phone,
            address=self.address or {},
            bio=self.bio,
            education=self.education or [],
            certifications=self.certifications or [],
            languages=self.languages or [],
            status=status,
            availability=self.availability or {},
            max_patients=max_patients,
            current_patient_count=current_patient_count,
            metadata=self.model_metadata or {},
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
