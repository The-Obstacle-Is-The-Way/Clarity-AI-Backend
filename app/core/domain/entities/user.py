"""
User Entity Module

This module defines the User entity and related types for the domain layer.
Following clean architecture principles, this module contains only domain entities
without any dependency on infrastructure or application layers.
"""

import enum
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRole(str, enum.Enum):
    """User roles within the system."""

    ADMIN = "admin"
    CLINICIAN = "clinician"
    PATIENT = "patient"
    RESEARCHER = "researcher"
    SYSTEM = "system"


class UserStatus(str, enum.Enum):
    """User account status within the system."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class User(BaseModel):
    """User domain entity representing a user in the system."""

    id: UUID | str = Field(..., description="Unique identifier for the user")
    username: str = Field(default="test_user", description="Username for login")
    email: EmailStr = Field(..., description="User's email address")
    first_name: str = Field(..., description="User's first name")
    last_name: str = Field(..., description="User's last name")
    roles: list[UserRole] | set[UserRole] | list[str] | set[str] = Field(
        default_factory=list, description="User's roles in the system"
    )
    is_active: bool = Field(True, description="Whether the user is active")
    status: UserStatus = Field(default=UserStatus.ACTIVE, description="User's account status")
    created_at: datetime = Field(default_factory=datetime.now, description="When the user was created")
    updated_at: datetime | None = Field(default=None, description="When the user was last updated")
    full_name: str | None = Field(default=None, description="User's full name (first + last)")

    # Authentication fields
    hashed_password: str = Field(
        default="dummy_password_hash", description="Hashed password for authentication"
    )
    password_hash: str = Field(
        default="dummy_password_hash", description="Alias for hashed_password"
    )
    
    # Alias for status to maintain compatibility with tests
    @property
    def account_status(self) -> UserStatus:
        """Alias for status to maintain compatibility with tests."""
        return self.status
    
    @account_status.setter
    def account_status(self, value: UserStatus) -> None:
        """Setter for account_status that updates status."""
        self.status = value

    # Modern Pydantic V2 configuration using ConfigDict
    model_config = ConfigDict(
        use_enum_values=True, 
        arbitrary_types_allowed=True,
        populate_by_name=True,  # Allow populating fields by alias
    )
    
    def __init__(self, **data: dict[str, any]):
        # Handle account_status if provided in constructor
        if "account_status" in data and "status" not in data:
            data["status"] = data.pop("account_status")
        super().__init__(**data)

    def has_role(self, role: UserRole | str) -> bool:
        """Check if the user has a specific role.

        Args:
            role: Role to check for (as enum or string)

        Returns:
            bool: True if the user has the role, False otherwise
        """
        role_value = role.value if hasattr(role, "value") else str(role)
        for user_role in self.roles:
            user_role_value = user_role.value if hasattr(user_role, "value") else str(user_role)
            if user_role_value == role_value:
                return True
        return False

    def has_any_role(self, roles: list[UserRole | str]) -> bool:
        """Check if the user has any of the specified roles.

        Args:
            roles: List of roles to check for (as enums or strings)

        Returns:
            bool: True if the user has any of the roles, False otherwise
        """
        for role in roles:
            if self.has_role(role):
                return True
        return False

    def __post_init__(self):
        """Populate full_name from first_name and last_name if not provided."""
        if self.full_name is None and self.first_name and self.last_name:
            self.full_name = f"{self.first_name} {self.last_name}"
