"""
User domain models for Novamind platform.

This module defines the core user entities and roles used throughout
the application, ensuring proper type safety and domain logic encapsulation.
"""

from enum import Enum
from typing import List, Optional

# Import ConfigDict for V2 style config
from pydantic import BaseModel, UUID4, Field, ConfigDict


class UserRole(str, Enum):
    """Enumeration of user roles within the Novamind platform."""
    ADMIN = "admin"
    PROVIDER = "provider"
    PATIENT = "patient"
    RESEARCHER = "researcher"
    SUPPORT = "support"


class User(BaseModel):
    """Core user entity representing a platform user."""
    id: UUID4 | str | None = None
    email: str
    hashed_password: str | None = None
    roles: List[UserRole] = []
    is_active: bool = True
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    # V2 Config
    model_config = ConfigDict(from_attributes=True)
