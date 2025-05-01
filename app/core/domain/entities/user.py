# -*- coding: utf-8 -*-
"""
User Entity Module.

Defines the User domain entity, representing a user (patient, provider, admin)
within the system. This entity encapsulates user authentication and authorization
data and related business logic. It is designed to be persistence-agnostic.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field, EmailStr, field_validator

class UserRole(str, Enum):
    """Enumeration for user roles."""
    PATIENT = "patient"
    PROVIDER = "provider"
    ADMIN = "admin"
    SYSTEM = "system" # For system-level operations

class User(BaseModel):
    """
    Represents a User in the domain layer.
    
    Attributes:
        id: Unique identifier for the user (UUID).
        username: Unique username used for login.
        email: User's email address.
        hashed_password: Securely hashed password.
        first_name: User's first name (optional).
        last_name: User's last name (optional).
        role: The role assigned to the user (e.g., patient, provider).
        is_active: Flag indicating if the user account is active.
        created_at: Timestamp when the user record was created.
        updated_at: Timestamp when the user record was last updated.
        last_login_at: Timestamp of the last successful login (optional).
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    username: str = Field(..., min_length=3, description="Unique username for login")
    email: EmailStr = Field(..., description="User's email address")
    hashed_password: str = Field(..., description="Hashed password")
    first_name: Optional[str] = Field(None, description="User's first name")
    last_name: Optional[str] = Field(None, description="User's last name")
    role: UserRole = Field(..., description="Role assigned to the user")
    is_active: bool = Field(default=True, description="Indicates if the user account is active")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    last_login_at: Optional[datetime] = Field(None, description="Timestamp of last successful login")

    model_config = {
        'from_attributes': True,
        'str_strip_whitespace': True,
        'validate_assignment': True,
        'use_enum_values': True  # Important for serialization of Enum
    }

    @field_validator('username', mode='before')
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

    def update_timestamp(self):
        """Updates the updated_at timestamp."""
        self.updated_at = datetime.now()

    def update_last_login(self):
        """Updates the last_login_at timestamp."""
        self.last_login_at = datetime.now()
        self.update_timestamp() # Also update the general updated_at timestamp

    def get_full_name(self) -> str:
        """Returns the full name of the user if available, otherwise username."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username 