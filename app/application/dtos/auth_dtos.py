"""
Authentication Data Transfer Objects (DTOs) module.

This module contains the DTOs used for authentication and authorization flows,
providing clean data structures for token management and user sessions.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, validator


class TokenPairDTO(BaseModel):
    """DTO representing a pair of access and refresh tokens."""
    
    access_token: str
    refresh_token: str


class LoginResponseDTO(BaseModel):
    """DTO representing the response to a successful login request."""
    
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: dict[str, Any]


class UserSessionDTO(BaseModel):
    """DTO representing an active user session."""
    
    session_id: str
    user_id: str
    email: str
    ip_address: str
    user_agent: str
    created_at: datetime
    expires_at: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }


class LoginRequestDTO(BaseModel):
    """DTO representing a login request."""
    
    email: EmailStr
    password: str
    
    @validator('password')
    def password_must_be_valid(cls, v):
        """Validate that the password field is not empty."""
        if not v or len(v) < 1:
            raise ValueError('Password cannot be empty')
        return v


class RefreshTokenRequestDTO(BaseModel):
    """DTO representing a token refresh request."""
    
    refresh_token: str
    
    @validator('refresh_token')
    def refresh_token_must_be_valid(cls, v):
        """Validate that the refresh token field is not empty."""
        if not v or len(v) < 10:  # Arbitrary minimum length for token validation
            raise ValueError('Invalid refresh token format')
        return v


class LogoutRequestDTO(BaseModel):
    """DTO representing a logout request."""
    
    all_sessions: bool = False 