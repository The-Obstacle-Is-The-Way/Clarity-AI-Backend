"""
SQLAlchemy model for Provider entity.

This module defines the SQLAlchemy ORM model for the Provider entity,
mapping the domain entity to the database schema.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional, Union, List, Dict, Any

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship

from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.types import GUID
from app.infrastructure.persistence.sqlalchemy.models.user import User

# Type-checking only imports to avoid circular imports
if TYPE_CHECKING:
    from app.domain.entities.provider import Provider as DomainProvider


class ProviderModel(Base):
    """
    SQLAlchemy model for the Provider entity.

    This model maps to the 'providers' table in the database and
    represents healthcare providers in the NOVAMIND system.
    """

    __tablename__ = "providers"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id"), nullable=False)
    specialty = Column(String(100), nullable=False)
    license_number = Column(String(100), nullable=False)
    npi_number = Column(String(20), nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=datetime.now,
        onupdate=datetime.now,
        nullable=False,
    )

    # Relationships with robust string references to avoid mapping issues
    # We only keep the User relationship for test purposes
    user = relationship(
        "User", 
        back_populates="provider",
        foreign_keys=[user_id],
        uselist=False,  # A provider belongs to a single user
        viewonly=True   # Make relationship viewonly to prevent synchronization errors
    )
    
    # Define all required relationships to ensure proper SQLAlchemy mapping
    # These relationships must be defined even in test environments to prevent sync errors
    
    # Define appointments relationship with proper viewonly to prevent sync errors
    appointments = relationship(
        "AppointmentModel", 
        back_populates="provider",
        lazy="selectin",  # Efficient loading pattern for related entities
        viewonly=True     # Prevents synchronization errors during tests
    )
    
    # Define medications relationship with proper viewonly setting
    medications = relationship(
        "MedicationModel", 
        back_populates="provider",
        lazy="selectin",
        viewonly=True     # Prevents synchronization errors during tests
    )
    
    # Define clinical_notes relationship with proper viewonly setting
    clinical_notes = relationship(
        "ClinicalNoteModel", 
        back_populates="provider",
        lazy="selectin",
        viewonly=True     # Prevents synchronization errors during tests
    )

    def __repr__(self) -> str:
        """Return string representation of the provider."""
        return f"<Provider(id={self.id}, specialty={self.specialty})>"

    @classmethod
    def from_domain(cls, provider: 'DomainProvider') -> 'ProviderModel':
        """
        Create a Provider model from domain entity.
        """
        # Extract user and domain data
        user_data = provider.user
        
        # Create user model if not exists
        # This will be handled by repository and UoW in real implementation
        user_model = User.from_domain(user_data) if user_data else None
        
        # Create provider model
        return cls(
            id=uuid.UUID(provider.id) if provider.id else uuid.uuid4(),
            user_id=user_model.id if user_model else None,
            specialty=provider.specialty,
            license_number=provider.license_number,
            npi=provider.npi,
            created_at=provider.created_at,
            updated_at=provider.updated_at,
            status=provider.status
        )

    def to_domain(self) -> 'DomainProvider':
        """
        Convert SQLAlchemy model instance to domain entity.

        Returns:
            DomainProvider: Domain entity instance
        """
        from app.domain.entities.provider import Provider, Specialty

        # Try to convert specialty string to Specialty enum if possible
        try:
            specialty = Specialty(self.specialty)
        except (ValueError, AttributeError):
            specialty = self.specialty

        return Provider(
            id=self.id,
            user_id=self.user_id,
            specialty=specialty,
            license_number=self.license_number,
            npi_number=self.npi_number,
            active=self.active,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
