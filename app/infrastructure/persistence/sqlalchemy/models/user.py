# -*- coding: utf-8 -*-
"""
SQLAlchemy models for user data.

This module defines the User SQLAlchemy model that follows HIPAA compliance
and clean architecture principles.
"""

import uuid
from typing import Any, Dict, List, Optional, Union
import enum
from datetime import datetime, timedelta
import json

import sqlalchemy as sa
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, ForeignKey, Enum, JSON
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID, JSONB
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy.orm import relationship

from app.infrastructure.persistence.sqlalchemy.models.base import Base

from app.domain.utils.datetime_utils import now_utc, UTC

import logging
logger = logging.getLogger(__name__)


class JSONType(TypeDecorator):
    """
    Platform-independent JSON type.
    
    Uses PostgreSQL's JSONB type when available, otherwise 
    uses TEXT type with JSON serialization for SQLite compatibility.
    """
    impl = TEXT
    cache_ok = True
    
    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            # Use native JSONB for PostgreSQL
            return dialect.type_descriptor(JSONB())
        else:
            # Use TEXT for SQLite and others
            return dialect.type_descriptor(TEXT())
    
    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == 'postgresql':
            return value  # PostgreSQL can handle JSON directly
        return json.dumps(value)  # For SQLite, serialize to JSON string
    
    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if dialect.name == 'postgresql':
            return value  # PostgreSQL already returns JSON
        try:
            return json.loads(value)  # For SQLite, deserialize from JSON string
        except (ValueError, TypeError):
            return None
            

class UUIDType(TypeDecorator):
    """
    Platform-independent UUID type.
    
    Uses PostgreSQL's UUID type when available, otherwise
    uses STRING type for SQLite compatibility.
    """
    impl = sa.String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            # Use native UUID for PostgreSQL
            return dialect.type_descriptor(PostgresUUID())
        else:
            # Use String for SQLite and others
            return dialect.type_descriptor(sa.String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        elif isinstance(value, str):
            return value
        else:
            return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, uuid.UUID):
            try:
                return uuid.UUID(value)
            except (ValueError, TypeError):
                return None
        return value


class UserRole(enum.Enum):
    """Enum representing possible user roles in the system."""
    ADMIN = "admin"
    CLINICIAN = "clinician"
    PATIENT = "patient"
    RESEARCHER = "researcher"
    SUPPORT = "support"


class User(Base):
    """
    SQLAlchemy model for user data.
    
    Represents the structure of the 'users' table.
    Following HIPAA compliance with restricted PII.
    """
    
    __tablename__ = "users"
    __table_args__ = {'extend_existing': True}
    
    # --- Core Identification and Metadata ---
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    
    # Password hash - never store plaintext passwords
    password_hash = Column(String(255), nullable=False)
    
    # User account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    
    # User role
    role = Column(Enum(UserRole), nullable=False, default=UserRole.PATIENT)
    
    # Audit fields
    created_at = Column(DateTime, default=now_utc, nullable=False)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc, nullable=False)
    last_login = Column(DateTime, nullable=True)
    
    # Security-related fields
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    account_locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=now_utc, nullable=False)
    
    # Token-related fields for password reset, account verification
    reset_token = Column(String(255), nullable=True)
    reset_token_expires_at = Column(DateTime, nullable=True)
    verification_token = Column(String(255), nullable=True)
    
    # Optional profile data - not PHI/PII
    first_name = Column(String(64), nullable=True)
    last_name = Column(String(64), nullable=True)
    
    # JSON fields for extensibility - using our custom cross-db JSONType
    preferences = Column(JSONType, nullable=True)  # User preferences (UI settings, etc.)
    
    # Relationships
    provider = relationship(
        "ProviderModel",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    patients = relationship(
        "Patient",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    
    # Audit logging
    access_logs = Column(JSONType, nullable=True)  # Stores recent access logs
    
    def __repr__(self) -> str:
        """Provide a non-PHI representation useful for debugging."""
        return f"<User(id={self.id}, username={self.username}, role={self.role}, created_at={self.created_at})>"
    
    def is_account_locked(self) -> bool:
        """Check if account is currently locked."""
        if not self.account_locked_until:
            return False
        return self.account_locked_until > now_utc()
    
    def increment_failed_login(self) -> None:
        """Increment failed login counter and maybe lock account."""
        self.failed_login_attempts += 1
        
        # Progressive lockout policy
        if self.failed_login_attempts >= 10:
            # Lock for 24 hours after 10 failures
            self.account_locked_until = now_utc() + timedelta(hours=24)
        elif self.failed_login_attempts >= 5:
            # Lock for 15 minutes after 5 failures
            self.account_locked_until = now_utc() + timedelta(minutes=15)
    
    def reset_failed_login(self) -> None:
        """Reset failed login counter after successful login."""
        self.failed_login_attempts = 0
        self.account_locked_until = None
    
    def record_login(self) -> None:
        """Record successful login."""
        self.last_login = now_utc()
        self.reset_failed_login()
    
    def generate_password_reset_token(self, expiry_hours: int = 24) -> str:
        """Generate a password reset token."""
        import secrets
        token = secrets.token_urlsafe(32)
        self.reset_token = token
        self.reset_token_expires_at = now_utc() + timedelta(hours=expiry_hours)
        return token
    
    def check_password_reset_token(self, token: str) -> bool:
        """Validate a password reset token."""
        if not self.reset_token or not self.reset_token_expires_at:
            return False
        if self.reset_token_expires_at < now_utc():
            return False
        return self.reset_token == token
    
    def clear_reset_token(self) -> None:
        """Clear password reset token after use."""
        self.reset_token = None
        self.reset_token_expires_at = None
    
    def password_needs_change(self, max_days: int = 90) -> bool:
        """Check if password needs to be changed based on age."""
        if not self.password_changed_at:
            return True
        password_age = now_utc() - self.password_changed_at
        return password_age.days > max_days
