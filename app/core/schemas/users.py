"""Core-layer user DTOs.

Shared across layers (domain, application, presentation) while remaining UI-
framework agnostic. Avoids duplicate definitions in tests.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, EmailStr, Field

__all__: list[str] = [
    "UserCreateRequest",
    "UserCreateResponse",
    "UserRead",
]


class _UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    roles: list[str] = Field(default_factory=list)


class UserCreateRequest(_UserBase):
    password: str = Field(..., min_length=8)


class UserCreateResponse(_UserBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime | None = None


class UserRead(_UserBase):
    id: UUID
    created_at: datetime
    updated_at: datetime | None = None
