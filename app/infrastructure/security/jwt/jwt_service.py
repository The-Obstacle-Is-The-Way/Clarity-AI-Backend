"""
JWT Service Implementation.

This service handles JWT token creation, validation, and management according to
HIPAA security standards and best practices for healthcare applications.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import jwt
from jwt.exceptions import DecodeError, ExpiredSignatureError, InvalidSignatureError
from pydantic import BaseModel, Field

# Import domain types for proper type safety
from app.core.domain.types.jwt_payload import (
    JWTPayload,
    RefreshTokenPayload,
    payload_from_dict,
)

# Import the correct interface
from app.core.interfaces.security.jwt_service_interface import IJwtService
from app.domain.enums.token_type import TokenType
from app.domain.exceptions import (
    InvalidTokenError,
    InvalidTokenException,
    TokenBlacklistedException,
    TokenExpiredException,
)

# Initialize logger
logger = logging.getLogger(__name__)


class TokenPayload(BaseModel):
    """Token payload model for validation.

    JWT claims spec: https://tools.ietf.org/html/rfc7519#section-4.1
    """

    # Required JWT claims (RFC 7519)
    iss: str | None = None  # Issuer
    subject: str | None = Field(None, alias="sub")  # Subject
    aud: str | list[str] | None = None  # Audience
    exp: int | None = None  # Expiration time
    nbf: int | None = None  # Not Before time
    iat: int | None = None  # Issued At time
    jti: str | None = None  # JWT ID

    # Token specific claims
    type: str | None = None  # Token type
    roles: list[str] = []  # User roles
    refresh: bool | None = None  # Is refresh token
    custom_fields: dict[str, Any] = {}  # Non-standard claims

    model_config = {
        "arbitrary_types_allowed": True,
        "extra": "allow",
        "populate_by_name": True,
    }

    @property
    def sub(self) -> str | None:
        """Get the subject as a string."""
        return str(self.subject) if self.subject is not None else None

    @sub.setter
    def sub(self, value: Any) -> None:
        """Set the subject value."""
        self.subject = str(value) if value is not None else None

    def get(self, key: str, default: Any = None) -> Any:
        """Dictionary-style get method for compatibility."""
        if key == "sub":
            return self.sub
        if hasattr(self, key):
            return getattr(self, key)
        if key in self.custom_fields:
            return self.custom_fields[key]
        return default


class JWTServiceImpl(IJwtService):
    """JWT Service implementation following SOLID principles.

    This service properly implements the IJwtService interface with
    type-safe method signatures and HIPAA-compliant security practices.
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
        issuer: str | None = None,
        audience: str | None = None,
        user_repository: Any | None = None,
        token_blacklist_repository: Any | None = None,
        audit_logger: Any | None = None,
        settings: Any | None = None,
    ):
        """Initialize the JWT service with proper configuration."""
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.issuer = issuer
        self.audience = audience
        self.user_repository = user_repository
        self.token_blacklist_repository = token_blacklist_repository
        self.audit_logger = audit_logger
        self.settings = settings
        self._token_blacklist: dict[str, dict[str, Any]] = {}

    async def create_access_token(
        self,
        user_id: str | UUID,
        roles: list[str] | None = None,
        expires_delta_minutes: int | None = None,
    ) -> str:
        """Create a JWT access token for authentication."""
        # Determine expiration time
        expires_minutes = expires_delta_minutes or self.access_token_expire_minutes
        expires_delta = timedelta(minutes=expires_minutes)

        # Calculate expiration timestamp
        now = datetime.now(timezone.utc)
        expires_at = now + expires_delta

        # Prepare claims
        claims = {
            "sub": str(user_id),
            "exp": int(expires_at.timestamp()),
            "iat": int(now.timestamp()),
            "type": TokenType.ACCESS.value,
            "roles": roles or [],
            "jti": str(uuid4()),
        }

        # Add optional claims
        if self.issuer:
            claims["iss"] = self.issuer
        if self.audience:
            claims["aud"] = self.audience

        # Create and return token
        return self._create_token(claims)

    async def create_refresh_token(
        self, user_id: str | UUID, expires_delta_minutes: int | None = None
    ) -> str:
        """Create a JWT refresh token."""
        # Convert minutes to days or use default (ensure float for timedelta)
        expires_days: float = float(self.refresh_token_expire_days)
        if expires_delta_minutes is not None:
            expires_days = expires_delta_minutes / (
                24 * 60
            )  # Convert to days (float for timedelta)

        expires_delta = timedelta(days=expires_days)

        # Calculate expiration timestamp
        now = datetime.now(timezone.utc)
        expires_at = now + expires_delta

        # Prepare claims
        claims = {
            "sub": str(user_id),
            "exp": int(expires_at.timestamp()),
            "iat": int(now.timestamp()),
            "type": TokenType.REFRESH.value,
            "refresh": True,
            "jti": str(uuid4()),
        }

        # Add optional claims
        if self.issuer:
            claims["iss"] = self.issuer
        if self.audience:
            claims["aud"] = self.audience

        # Create and return token
        return self._create_token(claims)

    async def verify_token(self, token: str) -> JWTPayload:
        """Verify a JWT token and return its payload."""
        try:
            # Decode the token
            payload = self._decode_token(token)

            # Check if token is blacklisted
            jti = payload.get("jti")
            if jti and await self._is_token_blacklisted(jti):
                raise TokenBlacklistedException("Token has been blacklisted")

            # Convert to structured JWTPayload
            payload_dict = self._extract_payload_dict(payload)
            jwt_payload = payload_from_dict(payload_dict)

            return jwt_payload

        except TokenBlacklistedException:
            raise
        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            raise InvalidTokenError(f"Token verification failed: {e}")

    def verify_refresh_token(self, refresh_token: str) -> RefreshTokenPayload:
        """Verify that a token is a valid refresh token."""
        try:
            # Decode the token
            payload = self._decode_token(refresh_token)

            # Verify it's a refresh token
            token_type = payload.get("type")
            is_refresh = token_type == TokenType.REFRESH.value or payload.get("refresh") is True

            if not is_refresh:
                raise InvalidTokenError("Token is not a refresh token")

            # Convert to RefreshTokenPayload
            payload_dict = self._extract_payload_dict(payload)
            return RefreshTokenPayload(**payload_dict)

        except Exception as e:
            logger.error(f"Error verifying refresh token: {e}")
            raise InvalidTokenError(f"Invalid refresh token: {e}")

    async def refresh_access_token(self, refresh_token: str) -> str:
        """Generate a new access token using a valid refresh token."""
        try:
            # Verify the refresh token
            payload = self.verify_refresh_token(refresh_token)

            # Extract user ID
            user_id = payload.sub
            if not user_id:
                raise InvalidTokenError("Refresh token missing user ID")

            # Create new access token with same roles
            return await self.create_access_token(user_id=user_id, roles=payload.roles)

        except Exception as e:
            logger.error(f"Error refreshing access token: {e}")
            raise InvalidTokenError(f"Token refresh failed: {e}")

    async def blacklist_token(self, token: str, expires_at: datetime) -> None:
        """Add a token to the blacklist."""
        try:
            # Decode token to get JTI
            payload = self._decode_token(token, verify_exp=False)
            jti = payload.get("jti")

            if not jti:
                jti = str(uuid4())  # Generate JTI if missing

            # Add to blacklist repository if available
            if self.token_blacklist_repository:
                await self.token_blacklist_repository.add_to_blacklist(jti, expires_at)

            # Add to in-memory blacklist
            self._token_blacklist[jti] = {
                "blacklisted_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": expires_at.isoformat(),
                "reason": "Explicitly blacklisted",
            }

        except Exception as e:
            logger.error(f"Error blacklisting token: {e}")
            raise InvalidTokenError(f"Token blacklisting failed: {e}")

    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if a token has been blacklisted."""
        try:
            # Decode token to get JTI
            payload = self._decode_token(token, verify_exp=False)
            jti = payload.get("jti")

            if not jti:
                return False

            return await self._is_token_blacklisted(jti)

        except Exception as e:
            logger.error(f"Error checking token blacklist: {e}")
            return False

    async def get_token_identity(self, token: str) -> str | UUID:
        """Extract the user identity from a token."""
        try:
            payload = self._decode_token(token)
            subject = payload.get("sub")

            if not subject:
                raise InvalidTokenError("Token does not contain identity")

            # Ensure subject is a string for proper typing
            subject_str = str(subject)

            # Try to return as UUID if possible, otherwise as string
            try:
                return UUID(subject_str)
            except ValueError:
                return subject_str

        except Exception as e:
            logger.error(f"Error extracting token identity: {e}")
            raise InvalidTokenError(f"Identity extraction failed: {e}")

    async def blacklist_session(self, session_id: str) -> bool:
        """Blacklist all tokens associated with a session.

        MVP implementation: if a token blacklist repository is available, delegate
        to it; otherwise, no-op and return ``False`` to indicate that session-wide
        revocation is not yet supported.
        """
        if self.token_blacklist_repository is None:
            # Not yet supported without repository – callers should not rely on this
            logger.debug("blacklist_session called but no repository configured")
            return False

        try:
            await self.token_blacklist_repository.blacklist_session_tokens(session_id)
            return True
        except Exception as exc:  # pragma: no cover – repository errors should not crash auth
            logger.warning("Error blacklisting session %s: %s", session_id, exc)
            return False

    def decode_token(
        self,
        token: str,
        verify_signature: bool = True,
        *,
        options: dict | None = None,
        audience: str | None = None,
        algorithms: list[str] | None = None,
    ) -> TokenPayload:  # type: ignore[override]
        """Decode a JWT token synchronously and return a validated payload.

        The implementation mirrors ``verify_token`` but without the blacklist
        checks so that unit-tests that call ``decode_token`` directly still work.
        """
        try:
            payload = self._decode_token(token)
        except InvalidTokenError as exc:
            raise exc

        payload_dict = self._extract_payload_dict(payload)
        return payload_from_dict(payload_dict)

    async def logout(self, token: str) -> bool:  # type: ignore[override]
        """Revoke a token by putting its JTI on the blacklist.

        This is a thin async wrapper around ``blacklist_token`` to satisfy the
        interface while keeping the underlying implementation synchronous.
        """
        try:
            payload = self._decode_token(token, verify_exp=False)
            exp_ts = payload.get(
                "exp", int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
            )
            await self.blacklist_token(token, datetime.fromtimestamp(exp_ts, tz=timezone.utc))  # type: ignore[arg-type]
            return True
        except Exception as exc:
            logger.warning("logout failed: %s", exc)
            return False

    def _create_token(self, claims: dict[str, Any]) -> str:
        """Create a JWT token with the given claims."""
        try:
            return jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
        except Exception as e:
            logger.error(f"Error creating token: {e}")
            raise InvalidTokenError(f"Token creation failed: {e}")

    def _decode_token(self, token: str, verify_exp: bool = True) -> TokenPayload:
        """Decode a JWT token and return its payload."""
        if not token:
            raise InvalidTokenException("Token is empty")

        # Remove 'Bearer ' prefix if present
        if token.startswith("Bearer "):
            token = token[7:]

        try:
            # Decode the token
            payload = jwt.decode(
                token=token,
                key=self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": verify_exp},
                audience=self.audience,
                issuer=self.issuer,
            )

            # Create TokenPayload object
            token_data: dict[str, Any] = {}
            custom_fields: dict[str, Any] = {}

            # Process all claims with proper type conversion
            for key, value in payload.items():
                if key == "sub":
                    token_data["subject"] = str(value)
                elif key == "roles":
                    if not isinstance(value, list):
                        token_data["roles"] = [value] if value else []
                    else:
                        token_data["roles"] = value
                elif key in ["exp", "nbf", "iat"] and value is not None:
                    # Convert timestamp fields to int
                    token_data[key] = int(value)
                elif key == "refresh" and value is not None:
                    # Convert refresh flag to bool
                    token_data[key] = bool(value)
                elif key in ["iss", "jti", "type"] and value is not None:
                    # Ensure string fields are strings
                    token_data[key] = str(value)
                elif key == "aud":
                    # Handle audience field (can be string or list[str])
                    if isinstance(value, list):
                        token_data[key] = value
                    elif value is not None:
                        token_data[key] = str(value)
                else:
                    # Add non-standard claims to custom_fields
                    standard_claims = [
                        "iss",
                        "sub",
                        "aud",
                        "exp",
                        "nbf",
                        "iat",
                        "jti",
                        "type",
                        "roles",
                        "refresh",
                    ]
                    if key not in standard_claims:
                        custom_fields[key] = value

            token_data["custom_fields"] = custom_fields
            return TokenPayload(**token_data)

        except ExpiredSignatureError as e:
            raise TokenExpiredException("Token has expired") from e
        except InvalidSignatureError as e:
            raise InvalidTokenException(f"Invalid token signature: {str(e)}")
        except DecodeError as e:
            raise InvalidTokenException(f"Invalid token: {str(e)}")
        except Exception as e:
            raise InvalidTokenException(f"Token decode error: {e}")

    def _extract_payload_dict(self, payload: TokenPayload) -> dict[str, Any]:
        """Extract payload data as dictionary for type conversion."""
        payload_dict = {}

        if hasattr(payload, "model_dump"):
            payload_dict = payload.model_dump()
        elif hasattr(payload, "__dict__"):
            payload_dict = payload.__dict__.copy()
        else:
            payload_dict = {}

        # Ensure required fields
        payload_dict.setdefault(
            "sub", str(payload.subject) if hasattr(payload, "subject") else "unknown"
        )
        payload_dict.setdefault("iat", int(datetime.now(timezone.utc).timestamp()))
        payload_dict.setdefault(
            "exp", int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        )
        payload_dict.setdefault("jti", str(uuid4()))
        payload_dict.setdefault("roles", [])
        payload_dict.setdefault("custom_fields", {})

        return payload_dict

    async def _is_token_blacklisted(self, jti: str) -> bool:
        """Check if a JTI is blacklisted."""
        # Check repository first
        if self.token_blacklist_repository:
            try:
                result = await self.token_blacklist_repository.is_blacklisted(jti)
                return bool(result)
            except Exception as e:
                logger.warning(f"Error checking blacklist repository: {e}")

        # Fallback to in-memory blacklist
        return jti in self._token_blacklist


def get_jwt_service(
    settings: Any,
    user_repository: Any = None,
    token_blacklist_repository: Any = None,
    audit_logger: Any = None,
) -> JWTServiceImpl:
    """Dependency injection factory for JWT service."""
    # Extract secret key from settings
    secret_key = None

    if hasattr(settings, "JWT_SECRET_KEY"):
        jwt_secret = settings.JWT_SECRET_KEY
        secret_key = (
            jwt_secret.get_secret_value()
            if hasattr(jwt_secret, "get_secret_value")
            else str(jwt_secret)
        )
    elif hasattr(settings, "SECRET_KEY"):
        secret_key_obj = settings.SECRET_KEY
        secret_key = (
            secret_key_obj.get_secret_value()
            if hasattr(secret_key_obj, "get_secret_value")
            else str(secret_key_obj)
        )

    if not secret_key:
        secret_key = "default-insecure-secret-key-for-testing-only"
        logger.warning("Using insecure default JWT secret key!")

    # Extract other settings
    algorithm = getattr(settings, "JWT_ALGORITHM", "HS256")
    access_token_expire_minutes = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 30)
    refresh_token_expire_days = getattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7)
    issuer = getattr(settings, "JWT_ISSUER", None)
    audience = getattr(settings, "JWT_AUDIENCE", None)

    return JWTServiceImpl(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
        issuer=issuer,
        audience=audience,
        user_repository=user_repository,
        token_blacklist_repository=token_blacklist_repository,
        audit_logger=audit_logger,
        settings=settings,
    )


# Alias export for backward compatibility with tests and older modules
# The public interface expected is `JWTService`, which maps to `JWTServiceImpl`.
JWTService = JWTServiceImpl  # type: ignore[valid-type]

# Explicit re-export list
__all__: list[str] = [
    "JWTServiceImpl",
    "JWTService",
    "get_jwt_service",
]
