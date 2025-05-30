"""User-related Pydantic schemas used by the API layer.

Follows Clean-Architecture: purely data-centric, no framework imports.
"""

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, EmailStr, Field

__all__ = [
    "UserCreateRequest",
    "UserCreateResponse",
    "UserRead",
]


class _UserBase(BaseModel):
    """Shared optional attributes between user schemas."""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr = Field(..., description="User e-mail used for login & notifications")
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)


class UserCreateRequest(_UserBase):
    """Payload for creating a new user via the public API."""

    # Use simple string with min_length constraint to avoid mypy incompatibility with `constr(...)`
    password: str = Field(..., min_length=8, description="Raw password to hash & store")


class UserCreateResponse(_UserBase):
    """Successful user-creation response payload."""

    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime | None = None


class UserRead(_UserBase):
    """Publicly exposed user model (e.g. in list / detail endpoints)."""

    id: UUID
    created_at: datetime
    updated_at: datetime | None = None
