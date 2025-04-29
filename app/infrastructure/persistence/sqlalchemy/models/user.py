# -*- coding: utf-8 -*-
"""
SQLAlchemy models for user data.

This module defines the User SQLAlchemy model that follows HIPAA compliance
and clean architecture principles. This is the CANONICAL SQLAlchemy model for User
and should be the only SQLAlchemy User model used throughout the application.

Architectural Note:
- This module implements the PERSISTENCE model for User entities
- The DOMAIN entity is in app.domain.entities.user
- Repository classes should handle conversion between domain and persistence models
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

# Import the canonical Base class
from app.infrastructure.persistence.sqlalchemy.models.base import Base, TimestampMixin, AuditMixin

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


class User(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for user data.
    
    Represents the structure of the 'users' table.
    Following HIPAA compliance with restricted PII.
    
    NOTE: This is the canonical SQLAlchemy User model and should be the only
    SQLAlchemy User model used in the application.
    """
    
    __tablename__ = "users"
    __table_args__ = {
        'extend_existing': True,
        'comment': 'User accounts with authentication and authorization information'
    }
    
    # --- Core Identification and Metadata ---
    id = Column(UUIDType, primary_key=True, default=uuid.uuid4, comment="Unique user identifier")
    username = Column(String(64), unique=True, nullable=False, comment="Username for login")
    email = Column(String(255), unique=True, nullable=False, index=True, comment="Email address for user contact")
    
    # Personal information - minimal necessary for function
    first_name = Column(String(100), nullable=True, comment="User's first name")
    last_name = Column(String(100), nullable=True, comment="User's last name")
    
    # Password hash - never store plaintext passwords
    password_hash = Column(String(255), nullable=False, comment="Securely hashed password")
    
    # User account status
    is_active = Column(Boolean, default=True, nullable=False, comment="Whether account is active")
    is_verified = Column(Boolean, default=False, nullable=False, comment="Whether account is verified")
    email_verified = Column(Boolean, default=False, nullable=False, comment="Whether email address is verified")
    
    # User role - using enum to enforce valid values
    role = Column(Enum(UserRole), nullable=False, default=UserRole.PATIENT, comment="Primary user role")
    
    # Roles are stored as a JSON array for more flexible role management
    roles = Column(JSONType, default=list, nullable=False, comment="List of all user roles")
    
    # Additional audit fields beyond the mixin
    last_login = Column(DateTime, nullable=True, comment="When user last logged in")
    
    # Security-related fields
    failed_login_attempts = Column(Integer, default=0, nullable=False, comment="Number of consecutive failed login attempts")
    account_locked_until = Column(DateTime, nullable=True, comment="When account lockout expires")
    password_changed_at = Column(DateTime, default=now_utc, nullable=False, comment="When password was last changed")
    
    # Token-related fields for password reset, account verification
    reset_token = Column(String(255), nullable=True, comment="Password reset token")
    reset_token_expires_at = Column(DateTime, nullable=True, comment="When reset token expires")
    verification_token = Column(String(255), nullable=True, comment="Account verification token")
    
    # Additional data
    bio = Column(Text, nullable=True, comment="Short bio for clinical staff")  
    preferences = Column(JSONType, nullable=True, comment="User UI and system preferences")  
    
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
    
    def __repr__(self):
        """String representation of the user."""
        return f"<User {self.username} ({self.id})>"
    
    def is_account_locked(self) -> bool:
        """Check if the account is locked due to failed logins."""
        if not self.account_locked_until:
            return False
        return self.account_locked_until > now_utc()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary representation suitable for API responses."""
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "role": self.role.value if self.role else None,
            "roles": self.roles if isinstance(self.roles, list) else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "phone_number": self.phone_number
        }
    
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
