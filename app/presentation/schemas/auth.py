from uuid import UUID
from typing import List, Optional

from pydantic import BaseModel, EmailStr

from app.core.domain.entities.user import UserStatus  # Assuming UserStatus is an Enum


class AuthCredentials(BaseModel):
    scopes: List[str] = []


class AuthenticatedUser(BaseModel):
    id: UUID
    username: str
    email: EmailStr
    roles: List[str] = []
    status: UserStatus
    # Optional: Add if these fields are commonly needed and available
    # first_name: Optional[str] = None
    # last_name: Optional[str] = None
    # last_login_at: Optional[datetime] = None

    class Config:
        orm_mode = True # Deprecated in Pydantic v2, use from_attributes = True
        # from_attributes = True # For Pydantic v2
