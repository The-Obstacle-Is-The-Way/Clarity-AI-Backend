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

import enum
import json
import logging
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import JSON, Boolean, Column, DateTime, Enum, Integer, String, Text, func, UUID
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship, declared_attr
from sqlalchemy.types import TEXT, TypeDecorator

from app.domain.utils.datetime_utils import now_utc

# Import the canonical Base and registry
from app.infrastructure.persistence.sqlalchemy.models.base import AuditMixin, Base, TimestampMixin
from app.infrastructure.persistence.sqlalchemy.registry import register_model
from app.infrastructure.persistence.sqlalchemy.types import JSONEncodedDict

logger = logging.getLogger(__name__)

# --- Define PK Column Separately --- 
user_id_column = Column(
    UUID(as_uuid=True),
    primary_key=True, 
    index=True,
    nullable=False,
    default=uuid.uuid4,
    comment="Unique user identifier - HIPAA compliance: Not PHI, used only for internal references"
)

class JSONType(TypeDecorator):
    """
    Platform-independent JSON type.
    
    Uses PostgreSQL\'s JSONB type when available, otherwise 
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
            

class UserRole(enum.Enum):
    """Enum representing possible user roles in the system."""
    ADMIN = "admin"
    CLINICIAN = "clinician"
    PATIENT = "patient"
    RESEARCHER = "researcher"
    SUPPORT = "support"


# Register the User model with our central registry to ensure proper mapping
# Define the canonical User model with proper SQLAlchemy mapping
@register_model
class User(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for user data.
    
    Represents the structure of the 'users' table.
    Following HIPAA compliance with restricted PII.
    
    NOTE: This is the canonical SQLAlchemy User model and should be the only
    SQLAlchemy User model used in the application.
    """
    
    __tablename__ = "users"
    __table_args__ = (
        # Example: Index for email if frequently searched
        # models.Index('ix_user_email', 'email'),
        # Ensure __table_args__ is a tuple, even with one item
        # (models.UniqueConstraint('username', name='uq_user_username'),)
        # Add other table-level constraints or indexes here if needed
        # No extend_existing here anymore
    )
    
    # --- Core Identification and Metadata ---
    id = user_id_column 
    username = Column(String(64), unique=True, nullable=False, comment="Username for login")
    email = Column(String(255), unique=True, nullable=False, index=True, comment="Email address for user contact")
    first_name = Column(String(100), nullable=True, comment="User's first name")
    last_name = Column(String(100), nullable=True, comment="User's last name")
    
    @declared_attr
    def phone_number(cls):
        return Column(String(20), nullable=True, unique=True, index=True, comment="User's phone number")
        
    password_hash = Column(String(255), nullable=False, comment="Securely hashed password")
    is_active = Column(Boolean, default=True, nullable=False, comment="Whether account is active")
    is_verified = Column(Boolean, default=False, nullable=False, comment="Whether account is verified")
    
    @declared_attr
    def email_verified(cls):
        return Column(Boolean, default=False, nullable=False, comment="Whether email address is verified")
        
    role = Column(Enum(UserRole), nullable=False, default=UserRole.PATIENT, comment="Primary user role")
    roles = Column(JSONEncodedDict, default=list, nullable=False, comment="List of all user roles")
    last_login = Column(DateTime, nullable=True, comment="When user last logged in")
    failed_login_attempts = Column(Integer, default=0, nullable=False, comment="Number of consecutive failed login attempts")
    account_locked_until = Column(DateTime, nullable=True, comment="When account lockout expires")
    reset_token = Column(String(255), nullable=True, comment="Password reset token")
    reset_token_expires_at = Column(DateTime, nullable=True, comment="When reset token expires")
    verification_token = Column(String(255), nullable=True, comment="Account verification token")
    bio = Column(Text, nullable=True, comment="Short bio for clinical staff")  
    preferences = Column(JSON, nullable=True, comment="User UI and system preferences")  

    # Explicitly define primary key for the mapper using the column object
    __mapper_args__ = {
        'primary_key': [user_id_column]
    }

    # --- Relationships (Simplified Again) --- 
    # Revert provider to simple state
    provider = relationship(
        "ProviderModel", 
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan"
        # Removed viewonly=True and foreign_keys string
    )
    
    patients = relationship(
        "Patient", 
        back_populates="user",
        cascade="all, delete-orphan"
    )
    
    # Relationship to AnalyticsEventModel 
    analytics_events = relationship(
        "AnalyticsEventModel", 
        back_populates="user", 
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    
    # Audit logging
    access_logs = Column(JSON, nullable=True)  # Stores recent access logs
    
    # Add property aliases for field name compatibility across layers
    @property
    def hashed_password(self) -> str:
        """Alias for password_hash to maintain compatibility with domain model."""
        return self.password_hash
        
    @hashed_password.setter
    def hashed_password(self, value: str) -> None:
        """Setter for hashed_password that updates password_hash."""
        self.password_hash = value
    
    def __repr__(self):
        """String representation of the user."""
        return f"<User {self.username} ({self.id})>"
    
    def is_account_locked(self) -> bool:
        """Check if the account is locked due to failed logins."""
        if not self.account_locked_until:
            return False
        return self.account_locked_until > now_utc()
    
    def password_needs_change(self, max_days: int = 90) -> bool:
        """Check if password needs to be changed based on age."""
        if not hasattr(self, 'password_changed_at') or not self.password_changed_at: # Check if attribute exists
            return True
        password_age = now_utc() - self.password_changed_at
        return password_age.days > max_days
    
    def to_dict(self) -> dict[str, Any]:
        """Convert user to dictionary representation suitable for API responses."""
        data = {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "role": self.role.value if self.role else None,
            "roles": self.roles if isinstance(self.roles, list) else [],
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "phone_number": self.phone_number
        }
        if hasattr(self, 'created_at') and self.created_at:
            data['created_at'] = self.created_at.isoformat()
        if hasattr(self, 'updated_at') and self.updated_at:
            data['updated_at'] = self.updated_at.isoformat()
        return data
    
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
