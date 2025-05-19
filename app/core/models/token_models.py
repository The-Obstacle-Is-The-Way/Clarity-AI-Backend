# backend/app/core/models/token_models.py

from __future__ import annotations

# NOTE: The codebase targets Python 3.9 in the CI matrix.
# While modern Python would use the `|` operator for union types (PEP-604),
# we must use typing.Union for Python 3.9 compatibility.
# The linter may suggest using X | Y syntax, but we must ignore these suggestions
# to maintain compatibility with Python 3.9.
from typing import Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field


class TokenPayload(BaseModel):
    """Schema for the data encoded within a JWT token.
    
    This is the canonical definition of TokenPayload used throughout the application.
    It includes all fields that might be needed by different parts of the system,
    including tests and authentication middleware.
    """
    # Standard JWT claims
    sub: Union[str, UUID]  # Subject of the token (user ID)
    exp: int  # Expiration time claim (POSIX timestamp)
    iat: int  # Issued at time claim (POSIX timestamp)
    iss: Optional[str] = None  # Issuer claim
    aud: Optional[Union[str, list[str]]] = None  # Audience claim
    jti: Optional[str] = None  # JWT ID claim
    nbf: Optional[int] = None  # Not before time
    
    # Application-specific fields
    scope: Optional[str] = None  # Single scope string (e.g. "access_token")
    scopes: Optional[list[str]] = Field(default_factory=list)  # Optional list variant
    session_id: Optional[str] = None  # Optional session identifier
    user_id: Optional[Union[str, UUID]] = None  # Explicit user identifier
    role: Optional[str] = None  # Single role string
    roles: Optional[list[str]] = None  # Multiple roles
    permissions: Optional[list[str]] = None  # Fine-grained permission list
    
    # Additional fields used in tests and other parts of the application
    username: Optional[str] = None  # Username
    email: Optional[str] = None  # User email
    token_type: Optional[str] = None  # Token type (access, refresh, etc.)
    first_name: Optional[str] = None  # User first name
    last_name: Optional[str] = None  # User last name
    is_active: Optional[bool] = None  # User active status
    is_verified: Optional[bool] = None  # User verification status
    active: Optional[bool] = None  # Alias for is_active
    verified: Optional[bool] = None  # Alias for is_verified
    refresh: Optional[bool] = None  # Flag for refresh tokens
    parent_jti: Optional[str] = None  # Parent token JTI for refresh token tracking
    type: Optional[str] = None  # Token type
    
    class Config:
        """Pydantic configuration for TokenPayload."""
        arbitrary_types_allowed = True
