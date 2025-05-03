# -*- coding: utf-8 -*-
"""
Pydantic schemas for User related data.
"""

from uuid import UUID
from typing import List, Optional
from pydantic import BaseModel, EmailStr, ConfigDict

class UserResponseSchema(BaseModel):
    """Schema for representing a user in API responses."""
    id: UUID
    username: str
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    roles: List[str] = []
    is_active: bool = True

    # V2 Config
    model_config = ConfigDict(from_attributes=True)
    # Use alias for consistency if needed, e.g., alias_generator = to_camel