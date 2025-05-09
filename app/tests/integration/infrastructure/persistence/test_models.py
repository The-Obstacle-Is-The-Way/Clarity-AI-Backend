"""
Simplified models for testing purposes.

This module provides simplified SQLAlchemy models for testing that don't have
dependencies on other models, ensuring clean table creation.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base

# from app.infrastructure.persistence.sqlalchemy.models.base import Base # Do NOT use shared Base

# Create a new Base for these test-specific models
TestMockBase = declarative_base()

class MockUser(TestMockBase):
    """
    Simplified User model for testing purposes.
    """
    __tablename__ = "users"
    # __table_args__ = {'extend_existing': True} # Not needed if using a separate Base/metadata
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    role = Column(String(50), nullable=False)
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)
    updated_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)
    last_login = Column(String, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(String, nullable=True)
    password_changed_at = Column(String, nullable=True)
    reset_token = Column(String(255), nullable=True)
    reset_token_expires_at = Column(String, nullable=True)
    verification_token = Column(String(255), nullable=True)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    preferences = Column(String(1000), nullable=True)

class TestPatient(TestMockBase):
    """
    Simplified Patient model for testing purposes.
    """
    __tablename__ = "patients"
    # __table_args__ = {'extend_existing': True} # Not needed if using a separate Base/metadata
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)
    updated_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Regular fields - no encryption in test models for simplicity
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    date_of_birth = Column(String, nullable=True, default=None)
    email = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)
    medical_record_number = Column(String(100), nullable=True)
    insurance_number = Column(String(100), nullable=True)
    gender = Column(String(50), nullable=True)
    allergies = Column(String(1000), nullable=True)
    medications = Column(String(1000), nullable=True)
    medical_history = Column(String(2000), nullable=True)
    treatment_notes = Column(String(2000), nullable=True)
    extra_data = Column(String(2000), nullable=True)
    address_line1 = Column(String(255), nullable=True)
    address_line2 = Column(String(255), nullable=True)
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    postal_code = Column(String(20), nullable=True)
    country = Column(String(100), nullable=True)
    emergency_contact = Column(String(1000), nullable=True)
    biometric_twin_id = Column(String(100), nullable=True)
    ssn = Column(String(15), nullable=True)  # Adding the missing SSN field
