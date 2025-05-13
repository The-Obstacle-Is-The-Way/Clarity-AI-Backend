"""
User Entity Module

This module defines the User entity and related types for the domain layer.
Following clean architecture principles, this module contains only domain entities
without any dependency on infrastructure or application layers.
"""

import enum
from datetime import datetime
from typing import List, Optional, Set, Union

from pydantic import BaseModel, EmailStr, Field


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
    
    id: str = Field(..., description="Unique identifier for the user")
    email: EmailStr = Field(..., description="User's email address")
    first_name: str = Field(..., description="User's first name")
    last_name: str = Field(..., description="User's last name")
    roles: Union[List[UserRole], Set[UserRole]] = Field(
        default_factory=list, description="User's roles in the system"
    )
    is_active: bool = Field(True, description="Whether the user is active")
    status: UserStatus = Field(
        default=UserStatus.ACTIVE, description="User's account status"
    )
    created_at: datetime = Field(
        ..., description="When the user was created"
    )
    updated_at: Optional[datetime] = Field(
        None, description="When the user was last updated"
    )
    
    class Config:
        """Pydantic configuration for the User entity."""
        
        use_enum_values = True

    def has_role(self, role: UserRole) -> bool:
        """Check if the user has a specific role.
        
        Args:
            role: Role to check for
            
        Returns:
            bool: True if the user has the role, False otherwise
        """
        return role in self.roles
        
    def has_any_role(self, roles: List[UserRole]) -> bool:
        """Check if the user has any of the specified roles.
        
        Args:
            roles: List of roles to check for
            
        Returns:
            bool: True if the user has any of the roles, False otherwise
        """
        return bool(set(roles) & set(self.roles))