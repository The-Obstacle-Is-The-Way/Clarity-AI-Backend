"""
SQLAlchemy user model for database operations.

This module defines the SQLAlchemy ORM model for users, which maps to a
database table and provides the data access layer for user operations.
"""
import uuid
from datetime import datetime, timedelta
from app.domain.utils.datetime_utils import now_utc, UTC
from app.domain.utils.datetime_utils import UTC
from typing import List

import sqlalchemy as sa
from sqlalchemy import JSON

from app.infrastructure.persistence.sqlalchemy.config.base import Base


class UserModel(Base):
    """
    SQLAlchemy ORM model for users.
    
    This model maps to the database 'users' table and contains
    columns for all user fields needed for authentication,
    authorization, and user identity.
    """
    __tablename__ = "users"
    
    # Primary key and identity
    # Use generic String to store UUID for cross-dialect support
    id = sa.Column(sa.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = sa.Column(sa.String, unique=True, index=True, nullable=True)  # Added for login compatibility
    email = sa.Column(sa.String, unique=True, index=True, nullable=False)
    first_name = sa.Column(sa.String, nullable=False)
    last_name = sa.Column(sa.String, nullable=False)
    
    # Authentication
    hashed_password = sa.Column(sa.String, nullable=False)
    is_active = sa.Column(sa.Boolean, default=True, nullable=False)
    
    # Authorization
    # Use JSON array for roles to support both PostgreSQL and SQLite
    roles = sa.Column(sa.JSON, default=list, nullable=False)
    
    # Audit fields
    created_at = sa.Column(sa.DateTime, default=now_utc, nullable=False)
    updated_at = sa.Column(
        sa.DateTime, 
        default=now_utc, 
        onupdate=now_utc,
        nullable=False
    )
    
    # Add SQLite compatibility for array type
    __table_args__ = {
        'sqlite_autoincrement': True,
    }
    
    def __repr__(self) -> str:
        """String representation of the user."""
        return f"<User {self.email}>"