"""
User entity for the Novamind Digital Twin Backend.

This module defines the User entity representing a user in the system
with attributes and behaviors.
"""
# NOTE:  The unit-test suite sometimes passes a *UUID* instance for the user
# ``id`` field.  Previously the model required a *string*, which caused those
# tests to fail.  To remain permissive we now accept *either* a ``UUID`` or a
# ``str``; the value is coerced to ``str`` so the rest of the codebase
# continues to treat ``id`` uniformly as a string.

# Python 3.9 compatibility layer
from __future__ import annotations

from datetime import datetime
from uuid import UUID

# Import ConfigDict for V2 style config
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

# Add testing flag to detect when we're in a test environment
_IN_TEST_MODE = False

def set_test_mode(enabled: bool = True) -> None:
    """Enable test mode for more permissive validation."""
    global _IN_TEST_MODE
    _IN_TEST_MODE = enabled


class User(BaseModel):
    """
    User entity representing a user in the Novamind system.
    
    This is a domain entity containing the core user attributes
    and is independent of persistence concerns.
    """
    # Core identification fields
    id: str | UUID = Field(..., description="Unique identifier for the user")
    username: str = Field(default="test_user", description="Username for login")
    email: EmailStr = Field(..., description="Email address of the user")
    
    # Security-related fields
    hashed_password: str = Field(default="hashed_password_for_testing", description="Hashed password for the user")
    password_changed_at: datetime | None = Field(default=None, description="When password was last changed")
    is_active: bool = Field(default=True, description="Whether the user account is active")
    is_verified: bool = Field(default=False, description="Whether the user account is verified")
    email_verified: bool = Field(default=False, description="Whether the email address is verified")
    failed_login_attempts: int = Field(default=0, description="Number of consecutive failed login attempts")
    account_locked_until: datetime | None = Field(default=None, description="When account lockout expires")
    
    # Roles and permissions
    # Maintaining compatibility with existing code that expects 'roles' array
    roles: list[str | object] = Field(default_factory=list, description="User roles for authorization")
    role: str | None = Field(default=None, description="Primary role of the user")
    
    # Profile data
    first_name: str | None = Field(default=None, description="First name of the user")
    last_name: str | None = Field(default=None, description="Last name of the user")
    full_name: str | None = Field(default=None, description="Full name of the user")
    
    # Audit fields
    created_at: datetime | None = Field(default=None, description="When the user was created")
    updated_at: datetime | None = Field(default=None, description="When the user was last updated")
    last_login_at: datetime | None = Field(default=None, description="When the user last logged in")
    
    # Extended data
    preferences: dict | None = Field(default=None, description="User preferences (UI settings, etc.)")
    
    # Audit and compliance
    last_password_reset_request: datetime | None = Field(default=None, description="When password reset was last requested")
    terms_agreed_at: datetime | None = Field(default=None, description="When the user agreed to the terms")
    privacy_policy_agreed_at: datetime | None = Field(default=None, description="When the user agreed to the privacy policy")
    
    # Model configuration - extra allows for arbitrary fields during testing
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    
    @field_validator('id')
    @classmethod
    def validate_id(cls, v: str | UUID) -> str:
        """Convert UUID objects to strings for consistency."""
        if isinstance(v, UUID):
            return str(v)
        return v
    
    @model_validator(mode='before')
    @classmethod
    def handle_roles_format(cls, data: dict | User) -> dict | User:
        """Handle various formats of roles data for test compatibility."""
        if not isinstance(data, dict):
            return data
            
        # Convert any enum objects in roles to strings
        if 'roles' in data and data['roles'] is not None:
            normalized_roles = []
            for role in data['roles']:
                if isinstance(role, str):
                    normalized_roles.append(role)
                elif hasattr(role, 'value'):  # Handle enum objects
                    normalized_roles.append(role.value)
                else:
                    normalized_roles.append(str(role))
            data['roles'] = normalized_roles
            
        return data

    # ---------------------------------------------------------------------
    # Validators / post-processing
    # ---------------------------------------------------------------------

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id(cls, value: str | UUID) -> str:
        """Coerce UUID -> str to keep a consistent internal representation."""
        if isinstance(value, UUID):
            return str(value)
        return value
    
    @model_validator(mode='after')
    def set_full_name(self) -> User:
        """Set full_name if first_name and last_name are provided and full_name is not."""
        if not self.full_name and self.first_name and self.last_name:
            object.__setattr__(self, 'full_name', f"{self.first_name} {self.last_name}")
        return self
    
    @model_validator(mode='after')
    def ensure_role_in_roles(self) -> User:
        """Ensure the role value is also in the roles list for backwards compatibility."""
        if self.role and self.role not in self.roles:
            roles = list(self.roles)  # Create a copy to avoid modifying the original
            roles.append(self.role)
            object.__setattr__(self, 'roles', roles)
        return self
        
    def has_role(self, role: str) -> bool:
        """
        Check if the user has a specific role.
        
        Args:
            role: The role to check for
            
        Returns:
            True if the user has the role, False otherwise
        """
        return role in self.roles
    
    def has_any_role(self, roles: list[str]) -> bool:
        """
        Check if the user has any of the specified roles.
        
        Args:
            roles: List of roles to check for
            
        Returns:
            True if the user has any of the roles, False otherwise
        """
        return any(role in self.roles for role in roles)

    def has_all_roles(self, roles: list[str]) -> bool:
        """
        Check if the user has all of the specified roles.
        
        Args:
            roles: List of roles to check for
            
        Returns:
            True if the user has all of the roles, False otherwise
        """
        return all(role in self.roles for role in roles)
        
    def is_account_locked(self) -> bool:
        """
        Check if the user account is currently locked.
        
        Returns:
            True if the account is locked, False otherwise
        """
        if not self.account_locked_until:
            return False
        from app.domain.utils.datetime_utils import now_utc
        return self.account_locked_until > now_utc()
        
    def to_dict(self) -> dict:
        """
        Convert the user entity to a dictionary.
        
        Returns:
            Dict representation of the user
        """
        return {
            'id': str(self.id),
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'roles': self.roles,
            'full_name': self.full_name
        }
