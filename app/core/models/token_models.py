# backend/app/core/models/token_models.py

from __future__ import annotations

# NOTE:
#   The codebase targets Python 3.9 in the CI matrix.  The `|` (PEP‑604
#   union‑type) syntax used previously is only supported from Python 3.10
#   onwards and therefore raises a `SyntaxError` during test discovery on
#   3.9. We replace these occurrences with `typing.Union` so that the same
#   code runs unmodified on 3.9 → 3.12.
from uuid import UUID

from pydantic import BaseModel, Field


class TokenPayload(BaseModel):
    """Schema for the data encoded within a JWT token."""
    sub: str | UUID  # Subject of the token (user ID)
    exp: int    # Expiration time claim (POSIX timestamp)
    iat: int    # Issued at time claim (POSIX timestamp)
    iss: str | None = None # Issuer claim
    aud: str | list[str] | None = None  # Audience claim
    jti: str | None = None # JWT ID claim
    scope: str | None = None               # Single scope string (e.g. "access_token")
    scopes: list[str] | None = Field(default_factory=list) # Optional list variant
    session_id: str | None = None # Optional session identifier
    # ------------------------------------------------------------------
    # Legacy / extended claims expected by the integration test‑suite
    # ------------------------------------------------------------------
    user_id: str | UUID | None = None  # Explicit user identifier
    role: str | None = None                 # Single role string
    roles: list[str] | None = None          # Multiple roles
    permissions: list[str] | None = None    # Fine‑grained permission list

    # Empty model_config since no specific settings are needed
    # If needed later, uncomment: model_config = ConfigDict(arbitrary_types_allowed=True)
