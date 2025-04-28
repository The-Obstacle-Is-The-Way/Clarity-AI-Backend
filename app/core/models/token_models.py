# backend/app/core/models/token_models.py

from __future__ import annotations
from pydantic import ConfigDict

# NOTE:
#   The codebase targets Python 3.9 in the CI matrix.  The `|` (PEP‑604
#   union‑type) syntax used previously is only supported from Python 3.10
#   onwards and therefore raises a `SyntaxError` during test discovery on
#   3.9. We replace these occurrences with `typing.Union` so that the same
#   code runs unmodified on 3.9 → 3.12.

from typing import Optional, List, Union
from uuid import UUID
from pydantic import BaseModel, Field
from datetime import datetime


class TokenPayload(BaseModel):
    """Schema for the data encoded within a JWT token."""
    sub: Union[str, UUID]  # Subject of the token (user ID)
    exp: int    # Expiration time claim (POSIX timestamp)
    iat: int    # Issued at time claim (POSIX timestamp)
    iss: Optional[str] = None # Issuer claim
    aud: Optional[Union[str, List[str]]] = None  # Audience claim
    jti: Optional[str] = None # JWT ID claim
    scope: Optional[str] = None               # Single scope string (e.g. "access_token")
    scopes: Optional[List[str]] = Field(default_factory=list) # Optional list variant
    session_id: Optional[str] = None # Optional session identifier
    # ------------------------------------------------------------------
    # Legacy / extended claims expected by the integration test‑suite
    # ------------------------------------------------------------------
    user_id: Optional[Union[str, UUID]] = None  # Explicit user identifier
    role: Optional[str] = None                 # Single role string
    roles: Optional[List[str]] = None          # Multiple roles
    permissions: Optional[List[str]] = None    # Fine‑grained permission list

    # Empty model_config since no specific settings are needed
    # If needed later, uncomment: model_config = ConfigDict(arbitrary_types_allowed=True)
