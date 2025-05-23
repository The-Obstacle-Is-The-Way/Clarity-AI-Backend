"""
Authentication Data Transfer Objects (DTOs) module.

This module contains the DTOs used for authentication and authorization flows,
providing clean data structures for token management and user sessions.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, field_validator


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

    model_config = {"json_encoders": {datetime: lambda dt: dt.isoformat()}}


class LoginRequestDTO(BaseModel):
    """DTO representing a login request."""

    username: str | None = None
    email: EmailStr | None = None
    password: str

    @field_validator("password")
    def password_must_be_valid(self, v):
        """Validate that the password field is not empty."""
        if not v or len(v) < 1:
            raise ValueError("Password cannot be empty")
        return v

    @field_validator("email", "username")
    def validate_credentials(self, v, info):
        """Validate that either username or email is provided."""
        # This will be called for both username and email fields
        # We'll check the model at the end to make sure one of them is set
        return v

    @classmethod
    def model_validate(cls, obj, *args, **kwargs):
        """Validate the model to ensure either username or email is provided."""
        model = super().model_validate(obj, *args, **kwargs)

        # After normal validation, check that at least one identifier is present
        if not model.username and not model.email:
            raise ValueError("Either username or email must be provided")

        return model


class RefreshTokenRequestDTO(BaseModel):
    """DTO representing a token refresh request."""

    refresh_token: str

    @field_validator("refresh_token")
    def refresh_token_must_be_valid(self, v):
        """Validate that the refresh token field is not empty."""
        if not v or len(v) < 10:  # Arbitrary minimum length for token validation
            raise ValueError("Invalid refresh token format")
        return v


class LogoutRequestDTO(BaseModel):
    """DTO representing a logout request."""

    all_sessions: bool = False
