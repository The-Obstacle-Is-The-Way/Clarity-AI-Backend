# backend/app/core/models/token_models.py

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TokenPayload(BaseModel):
    """Schema for the data encoded within a JWT token.

    This is the canonical definition of TokenPayload used throughout the application.
    It includes all fields that might be needed by different parts of the system,
    including tests and authentication middleware.
    """

    # Standard JWT claims
    sub: str | UUID  # Subject of the token (user ID)
    exp: int  # Expiration time claim (POSIX timestamp)
    iat: int  # Issued at time claim (POSIX timestamp)
    iss: str | None = None  # Issuer claim
    aud: str | list[str] | None = None  # Audience claim
    jti: str | None = None  # JWT ID claim
    nbf: int | None = None  # Not before time

    # Application-specific fields
    scope: str | None = None  # Single scope string (e.g. "access_token")
    scopes: list[str] | None = Field(default_factory=list)  # Optional list variant
    session_id: str | None = None  # Optional session identifier
    user_id: str | UUID | None = None  # Explicit user identifier
    role: str | None = None  # Single role string
    roles: list[str] | None = None  # Multiple roles
    permissions: list[str] | None = None  # Fine-grained permission list

    # Additional fields used in tests and other parts of the application
    username: str | None = None  # Username
    email: str | None = None  # User email
    token_type: str | None = None  # Token type (access, refresh, etc.)
    first_name: str | None = None  # User first name
    last_name: str | None = None  # User last name
    is_active: bool | None = None  # User active status
    is_verified: bool | None = None  # User verification status
    active: bool | None = None  # Alias for is_active
    verified: bool | None = None  # Alias for is_verified
    refresh: bool | None = None  # Flag for refresh tokens
    parent_jti: str | None = None  # Parent token JTI for refresh token tracking
    type: str | None = None  # Token type

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",  # Allow extra fields for forward compatibility
        populate_by_name=True,  # Allow populating by field name
    )

    # ---------------------------------------------------------------------
    # Dict-like helpers for compatibility with legacy code expecting dicts
    # ---------------------------------------------------------------------

    def get(self, key: str, default: Any | None = None) -> Any:
        """Dictionary-style access helper.

        Older parts of the codebase (and some external libraries) still treat the
        JWT *payload* as a plain mapping and access fields via ``payload.get(...)``.
        To avoid widespread refactors we expose a thin helper that proxies to
        ``getattr`` and keeps *mypy* satisfied by guaranteeing a return value of
        ``Any``.
        """

        return getattr(self, key, default)

    # Support ``in`` checks (``key in payload``)
    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    # Allow index access ``payload["sub"]``
    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)
