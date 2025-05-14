from uuid import UUID

from pydantic import BaseModel, EmailStr

from app.core.domain.entities.user import UserRole, UserStatus


class AuthCredentials(BaseModel):
    scopes: list[str] = []


class AuthenticatedUser(BaseModel):
    id: UUID
    username: str
    email: EmailStr
    roles: list[UserRole] = []
    status: UserStatus
    # Optional: Add if these fields are commonly needed and available
    # first_name: str = None
    # last_name: str = None
    # last_login_at: datetime = None

    class Config:
        from_attributes = True  # For Pydantic v2
