"""
Pydantic schemas for User related data.
"""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr


class UserResponseSchema(BaseModel):
    """Schema for representing a user in API responses."""
    id: UUID
    username: str
    email: EmailStr | None = None
    full_name: str | None = None
    roles: list[str] = []
    is_active: bool = True

    # V2 Config
    model_config = ConfigDict(from_attributes=True)
    # Use alias for consistency if needed, e.g., alias_generator = to_camel