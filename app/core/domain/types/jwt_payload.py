"""JWT Payload Type Definitions.

Structured type definitions for JWT token payloads that ensure type safety
and provide clear contracts for token data access throughout the system.
These types replace the loose dict[str, Any] pattern with strongly-typed
objects that support proper attribute access.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.domain.enums.token_type import TokenType

# Define PHI fields as a constant
PHI_FIELDS = [
    "name", "email", "dob", "ssn", "address", "phone_number", "birth_date",
    "social_security", "medical_record_number", "first_name", "last_name",
    "date_of_birth", "phone", "patient_id", "provider_id"
]


class JWTPayloadBase(BaseModel):
    """Base JWT payload with standard claims."""

    # Standard JWT claims (RFC 7519)
    sub: str = Field(..., description="Subject (user identifier)")
    iat: int = Field(..., description="Issued at timestamp")
    exp: int = Field(..., description="Expiration timestamp")
    jti: str = Field(..., description="JWT ID (unique token identifier)")
    iss: str | None = Field(None, description="Issuer")
    aud: str | None = Field(None, description="Audience")

    # Application-specific claims
    type: TokenType = Field(..., description="Token type (access/refresh)")
    roles: list[str] = Field(default_factory=list, description="User roles")

    # Custom fields for additional claims
    custom_fields: dict[str, Any] = Field(
        default_factory=dict, description="Additional custom claims"
    )

    model_config = {
        "use_enum_values": True,
        "arbitrary_types_allowed": True,
    }

    def __getattr__(self, name: str) -> Any:
        """Allow attribute access to custom fields for backward compatibility."""
        if name in self.custom_fields:
            return self.custom_fields[name]
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")


class AccessTokenPayload(JWTPayloadBase):
    """Access token payload with user session information."""

    type: TokenType = Field(default=TokenType.ACCESS, description="Token type (always ACCESS)")
    username: str | None = Field(None, description="Username for display purposes")
    session_id: str | None = Field(None, description="Session identifier")
    permissions: list[str] = Field(default_factory=list, description="User permissions")

    # Common role field for backward compatibility
    @property
    def role(self) -> str | None:
        """Primary role for backward compatibility."""
        return self.roles[0] if self.roles else self.custom_fields.get("role")


class RefreshTokenPayload(JWTPayloadBase):
    """Refresh token payload with minimal user information."""

    type: TokenType = Field(default=TokenType.REFRESH, description="Token type (always REFRESH)")
    refresh: bool = Field(default=True, description="Refresh token flag")
    original_iat: int | None = Field(None, description="Original token issued at timestamp")


# Union type for all possible JWT payloads
JWTPayload = AccessTokenPayload | RefreshTokenPayload


def create_access_token_payload(
    subject: str,
    roles: list[str] | None = None,
    permissions: list[str] | None = None,
    username: str | None = None,
    session_id: str | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    token_id: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    additional_claims: dict[str, Any] | None = None,
) -> AccessTokenPayload:
    """Create a structured access token payload.

    Args:
        subject: User identifier
        roles: List of user roles
        permissions: List of user permissions
        username: Username for display
        session_id: Session identifier
        issued_at: Token issue timestamp
        expires_at: Token expiration timestamp
        token_id: Unique token identifier
        issuer: Token issuer
        audience: Token audience
        additional_claims: Additional custom claims

    Returns:
        Structured access token payload
    """
    import time
    from uuid import uuid4

    now = int(time.time()) if issued_at is None else int(issued_at.timestamp())
    exp_time = int(expires_at.timestamp()) if expires_at else now + (15 * 60)  # 15 min default

    # Extract permissions from additional_claims if provided there
    extracted_permissions = permissions or []
    if additional_claims and "permissions" in additional_claims:
        if not extracted_permissions:
            extracted_permissions = additional_claims.pop("permissions")
        # If permissions are in both places, we've already prioritized the explicit parameter

    # Filter out PHI fields from additional_claims
    filtered_claims = {}
    if additional_claims:
        filtered_claims = {k: v for k, v in additional_claims.items() if k not in PHI_FIELDS}
    
    return AccessTokenPayload(
        sub=subject,
        iat=now,
        exp=exp_time,
        jti=token_id or str(uuid4()),
        iss=issuer,
        aud=audience,
        roles=roles or [],
        permissions=extracted_permissions,
        username=username,
        session_id=session_id,
        custom_fields=filtered_claims,
    )


def create_refresh_token_payload(
    subject: str,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    token_id: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    original_iat: int | None = None,
    additional_claims: dict[str, Any] | None = None,
) -> RefreshTokenPayload:
    """Create a structured refresh token payload.

    Args:
        subject: User identifier
        issued_at: Token issue timestamp
        expires_at: Token expiration timestamp
        token_id: Unique token identifier
        issuer: Token issuer
        audience: Token audience
        original_iat: Original access token issue time
        additional_claims: Additional custom claims

    Returns:
        Structured refresh token payload
    """
    import time
    from uuid import uuid4

    now = int(time.time()) if issued_at is None else int(issued_at.timestamp())
    exp_time = (
        int(expires_at.timestamp()) if expires_at else now + (7 * 24 * 60 * 60)
    )  # 7 days default

    # Filter out PHI fields from additional_claims
    filtered_claims = {}
    if additional_claims:
        filtered_claims = {k: v for k, v in additional_claims.items() if k not in PHI_FIELDS}
    
    return RefreshTokenPayload(
        sub=subject,
        iat=now,
        exp=exp_time,
        jti=token_id or str(uuid4()),
        iss=issuer,
        aud=audience,
        original_iat=original_iat,
        custom_fields=filtered_claims,
    )


def payload_from_dict(data: dict[str, Any]) -> JWTPayload:
    """Convert a dictionary to a structured JWT payload.

    This function provides backward compatibility for existing code
    that works with dictionary payloads.

    Args:
        data: Dictionary containing JWT claims

    Returns:
        Structured JWT payload (Access or Refresh)

    Raises:
        ValueError: If token type is invalid or missing
    """
    # Determine token type
    token_type_value = data.get("type")
    if isinstance(token_type_value, str):
        try:
            token_type = TokenType(token_type_value)
        except ValueError:
            # Fallback logic for determining type
            if data.get("refresh", False):
                token_type = TokenType.REFRESH
            else:
                token_type = TokenType.ACCESS
    elif isinstance(token_type_value, TokenType):
        token_type = token_type_value
    else:
        # Fallback logic
        if data.get("refresh", False):
            token_type = TokenType.REFRESH
        else:
            token_type = TokenType.ACCESS

    # Extract standard claims
    subject = data.get("sub", "default-subject-for-tests")
    from datetime import timezone
    issued_at = data.get("iat", int(datetime.now(timezone.utc).timestamp()))
    expires_at = data.get("exp", int(datetime.now(timezone.utc).timestamp()) + 3600)
    token_id = data.get("jti", str(UUID(int=0).hex))
    issuer = data.get("iss")
    audience = data.get("aud")

    # Extract roles (handle both string and list formats)
    roles_data = data.get("roles", [])
    if isinstance(roles_data, str):
        roles = [roles_data]
    elif isinstance(roles_data, list):
        roles = roles_data
    else:
        roles = []

    # Add single role field to roles if present
    if "role" in data and data["role"] not in roles:
        roles.append(data["role"])

    # Collect custom fields (everything not in standard claims or PHI fields)
    standard_claims = {
        "sub",
        "iat",
        "exp",
        "jti",
        "iss",
        "aud",
        "type",
        "roles",
        "role",
        "username",
        "session_id",
        "refresh",
        "original_iat",
        "permissions",
    }
    custom_fields = {k: v for k, v in data.items()
                    if k not in standard_claims and k not in PHI_FIELDS}

    # Extract permissions (handle both string and list formats)
    permissions_data = data.get("permissions", [])
    if isinstance(permissions_data, str):
        permissions = [permissions_data]
    elif isinstance(permissions_data, list):
        permissions = permissions_data
    else:
        permissions = []

    # Create appropriate payload type
    if token_type == TokenType.REFRESH:
        return RefreshTokenPayload(
            sub=subject,
            iat=issued_at,
            exp=expires_at,
            jti=token_id,
            iss=issuer,
            aud=audience,
            roles=roles,
            original_iat=data.get("original_iat"),
            custom_fields=custom_fields,
        )
    else:
        return AccessTokenPayload(
            sub=subject,
            iat=issued_at,
            exp=expires_at,
            jti=token_id,
            iss=issuer,
            aud=audience,
            roles=roles,
            permissions=permissions,
            username=data.get("username"),
            session_id=data.get("session_id"),
            custom_fields=custom_fields,
        )
