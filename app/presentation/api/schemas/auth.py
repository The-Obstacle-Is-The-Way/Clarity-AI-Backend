"""
Pydantic schemas for authentication-related requests and responses.
"""
import uuid
from typing import List, Optional # Corrected from list

from pydantic import BaseModel, EmailStr, Field

class TokenDataSchema(BaseModel):
    """Schema for data embedded within a token."""
    sub: str = Field(..., description="Subject of the token (usually user ID)")
    roles: Optional[List[str]] = Field(None, description="User roles")
    # Add other custom claims as needed

class TokenResponseSchema(BaseModel):
    """Response schema for successful login or token refresh."""
    access_token: str = Field(..., description="JWT Access Token")
    refresh_token: str = Field(..., description="JWT Refresh Token")
    token_type: str = Field("bearer", description="Type of the token")
    expires_in: int = Field(..., description="Seconds until access token expiration")
    user_id: Optional[uuid.UUID] = Field(None, description="User ID of the authenticated user") # Added Optional
    roles: Optional[List[str]] = Field(None, description="Roles of the authenticated user")

    class Config:
        from_attributes = True #  Updated from orm_mode = True for Pydantic v2

class LoginRequestSchema(BaseModel):
    """Request schema for user login."""
    username: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")
    remember_me: bool = Field(False, description="Whether to issue a long-lived refresh token")

class RefreshTokenRequestSchema(BaseModel):
    """Request schema for refreshing an access token."""
    refresh_token: str = Field(..., description="The refresh token")

class SessionInfoResponseSchema(BaseModel):
    """Response schema for the session information endpoint."""
    authenticated: bool = Field(..., description="Whether the user is currently authenticated")
    session_active: bool = Field(..., description="Whether there is an active session (e.g., valid token)")
    user_id: Optional[uuid.UUID] = Field(None, description="User ID if authenticated")
    roles: Optional[List[str]] = Field(None, description="User roles if authenticated")
    permissions: Optional[List[str]] = Field(None, description="User permissions if authenticated")
    exp: Optional[int] = Field(None, description="Access token expiry timestamp (seconds since epoch)")
    # Add other relevant session details like CSRF token if used

    class Config:
        from_attributes = True

class UserRegistrationRequestSchema(BaseModel):
    """Request schema for new user registration."""
    email: EmailStr = Field(..., description="User's email for registration")
    password: str = Field(..., min_length=8, description="User's chosen password (min 8 characters)")
    full_name: Optional[str] = Field(None, max_length=100, description="User's full name")
    # Add other fields like terms_accepted, etc.

class UserRegistrationResponseSchema(BaseModel):
    """Response schema after successful user registration."""
    id: uuid.UUID = Field(..., description="Newly created user's ID")
    email: EmailStr = Field(..., description="User's email")
    is_active: bool = Field(..., description="Whether the user account is active (usually True after registration)")
    is_verified: bool = Field(False, description="Whether the user's email has been verified (usually False initially)")

    class Config:
        from_attributes = True

class LogoutResponseSchema(BaseModel):
    """Response schema for logout (though often logout is 204 No Content)."""
    message: str = Field("Successfully logged out", description="Logout confirmation message")

# You might also want a schema for password change, password reset requests, etc.
# Example:
# class PasswordChangeRequestSchema(BaseModel):
#     current_password: str
#     new_password: str

# class ForgotPasswordRequestSchema(BaseModel):
#     email: EmailStr

# class ResetPasswordRequestSchema(BaseModel):
#     token: str
#     new_password: str 