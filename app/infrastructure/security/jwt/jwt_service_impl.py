"""Implementation of JWT service for authentication, authorization, and token management.

Follows clean architecture principles by implementing the IJwtService interface
and handling JWT token creation, validation, and management for HIPAA compliance.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Union, Any
from uuid import UUID, uuid4

from jose import ExpiredSignatureError, JWTError
from jose import jwt as jose_jwt

from app.core.audit.audit_logger import IAuditLogger
from app.core.audit.audit_service import AuditEventType
from app.core.config.settings import Settings
from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException
from app.domain.interfaces.repository.token_blacklist_repository import ITokenBlacklistRepository
from app.domain.interfaces.repository.user_repository import IUserRepository
from app.infrastructure.security.jwt.i_jwt_service import IJwtService

# Configure logging
logger = logging.getLogger(__name__)

# Use jwt functions directly for clarity
jwt_encode = jose_jwt.encode
jwt_decode = jose_jwt.decode

# Test key for development use only - override in production
TEST_SECRET_KEY = "test_secret_key_for_development_only"


class JWTServiceImpl(IJwtService):
    """Implementation of JWT service for token creation, validation, and management.
    
    This service provides all the functionality required for handling JWT tokens,
    including token creation, validation, revocation, and blacklisting.
    Implements HIPAA-compliant token management with appropriate security controls.
    """
    
    def __init__(
        self,
        settings: Optional[Settings] = None,
        token_blacklist_repository: Optional[ITokenBlacklistRepository] = None,
        audit_logger: Optional[IAuditLogger] = None,
        user_repository: Optional[IUserRepository] = None,
        # Additional parameters for direct initialization (test compatibility)
        secret_key: Optional[str] = None,
        algorithm: Optional[str] = None,
        access_token_expire_minutes: Optional[int] = None,
        refresh_token_expire_days: Optional[int] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
    ):
        """Initialize JWT service with necessary dependencies.

        Args:
            settings: Application settings for JWT configuration
            token_blacklist_repository: Repository for token blacklisting
            audit_logger: Service for audit logging
            user_repository: Repository for user data access
            secret_key: JWT secret key (test compatibility)
            algorithm: JWT algorithm (test compatibility)
            access_token_expire_minutes: Access token expiry in minutes (test compatibility)
            refresh_token_expire_days: Refresh token expiry in days (test compatibility)
            issuer: Token issuer (test compatibility)
            audience: Token audience (test compatibility)
        """
        self.settings = settings
        self.token_blacklist_repository = token_blacklist_repository
        self.audit_logger = audit_logger
        self.user_repository = user_repository

        # JWT settings - prioritize direct parameters over settings
        if secret_key:
            self._secret_key = secret_key
        elif settings and hasattr(settings, "jwt_secret_key"):
            self._secret_key = settings.jwt_secret_key
        else:
            self._secret_key = TEST_SECRET_KEY

        if algorithm:
            self._algorithm = algorithm
        elif settings and hasattr(settings, "jwt_algorithm"):
            self._algorithm = settings.jwt_algorithm
        else:
            self._algorithm = "HS256"

        if access_token_expire_minutes:
            self._access_token_expire_minutes = access_token_expire_minutes
        elif settings and hasattr(settings, "access_token_expire_minutes"):
            self._access_token_expire_minutes = int(settings.access_token_expire_minutes)
        else:
            self._access_token_expire_minutes = 15

        # Handle refresh token expiry in days or minutes
        if refresh_token_expire_days:
            self._refresh_token_expire_minutes = refresh_token_expire_days * 24 * 60
        elif settings and hasattr(settings, "refresh_token_expire_minutes"):
            self._refresh_token_expire_minutes = int(settings.refresh_token_expire_minutes)
        else:
            self._refresh_token_expire_minutes = 10080  # Default to 7 days in minutes

        # Store audience and issuer - these are important for JWT validation
        if audience:
            self._token_audience = audience
        elif settings and hasattr(settings, "token_audience"):
            self._token_audience = settings.token_audience
        else:
            self._token_audience = ""

        if issuer:
            self._token_issuer = issuer
        elif settings and hasattr(settings, "token_issuer"):
            self._token_issuer = settings.token_issuer
        else:
            self._token_issuer = ""

        # In-memory blacklist for testing when no repository is provided
        self._token_blacklist = {}

        logger.info(f"JWT Service initialized with algorithm {self._algorithm}")

    
    def __init__(
        self,
        settings: Settings | None = None,
        token_blacklist_repository: ITokenBlacklistRepository | None = None,
        audit_logger: IAuditLogger | None = None,
        user_repository: IUserRepository | None = None,
        # Additional parameters for direct initialization (test compatibility)
        secret_key: str | None = None,
        algorithm: str | None = None,
        access_token_expire_minutes: int | None = None,
        refresh_token_expire_days: int | None = None,
        issuer: str | None = None,
        audience: str | None = None,
    ):
        """Initialize JWT service with necessary dependencies.

        Args:
            settings: Application settings for JWT configuration
            token_blacklist_repository: Repository for token blacklisting
            audit_logger: Service for audit logging
            user_repository: Repository for user data access
            secret_key: JWT secret key (test compatibility)
            algorithm: JWT algorithm (test compatibility)
            access_token_expire_minutes: Access token expiry in minutes (test compatibility)
            refresh_token_expire_days: Refresh token expiry in days (test compatibility)
            issuer: Token issuer (test compatibility)
            audience: Token audience (test compatibility)
        """
        self.settings = settings
        self.token_blacklist_repository = token_blacklist_repository
        self.audit_logger = audit_logger
        self.user_repository = user_repository

        # JWT settings - prioritize direct parameters over settings
        if secret_key:
            self._secret_key = secret_key
        elif settings and hasattr(settings, "jwt_secret_key"):
            self._secret_key = settings.jwt_secret_key
        else:
            self._secret_key = TEST_SECRET_KEY

        if algorithm:
            self._algorithm = algorithm
        elif settings and hasattr(settings, "jwt_algorithm"):
            self._algorithm = settings.jwt_algorithm
        else:
            self._algorithm = "HS256"

        if access_token_expire_minutes:
            self._access_token_expire_minutes = access_token_expire_minutes
        elif settings:
            # Check both uppercase and lowercase for compatibility
            access_token_expire = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", None) or getattr(
                settings, "access_token_expire_minutes", 15
            )
            # Ensure we have an integer value
            self._access_token_expire_minutes = (
                int(access_token_expire) if access_token_expire is not None else 15
            )
        else:
            self._access_token_expire_minutes = 15

        # Handle refresh token expiry in days or minutes
        if refresh_token_expire_days:
            self._refresh_token_expire_minutes = refresh_token_expire_days * 24 * 60
        elif settings and hasattr(settings, "refresh_token_expire_minutes"):
            self._refresh_token_expire_minutes = (
                int(settings.refresh_token_expire_minutes)
                if settings.refresh_token_expire_minutes is not None
                else 10080
            )
        else:
            self._refresh_token_expire_minutes = 10080  # Default to 7 days in minutes

        # Store audience and issuer - these are important for JWT validation
        if audience:
            self._token_audience = audience
        elif settings and hasattr(settings, "token_audience"):
            self._token_audience = settings.token_audience
        else:
            self._token_audience = ""

        if issuer:
            self._token_issuer = issuer
        elif settings and hasattr(settings, "token_issuer"):
            self._token_issuer = settings.token_issuer
        else:
            self._token_issuer = ""

        # Backward compatibility attributes
        self.audience = self._token_audience
        self.issuer = self._token_issuer

        # In-memory blacklist for testing when no repository is provided
        self._token_blacklist = {}

        logger.info(f"JWT Service initialized with algorithm {self._algorithm}")
    
    async def create_access_token(
        self,
        user_id: str | UUID,
        roles: list[str] | None = None,
        expires_delta_minutes: int | None = None,
        additional_claims: dict | None = None,
    ) -> str:
        """
        Create a JWT access token for authentication.

        Args:
            user_id: The user ID to encode in the token
            roles: The user roles to encode in the token
            expires_delta_minutes: Custom expiration time in minutes
            additional_claims: Optional additional claims to include in the token

        Returns:
            JWT access token as a string
        """
    async def _encode_token(self, payload: dict) -> str:
        """Encode a payload into a JWT token string.
        
        Args:
            payload: Dictionary containing claims to encode
            
        Returns:
            JWT token as a string
        """
        return jwt_encode(payload, self._secret_key, algorithm=self._algorithm)
    
    async def _decode_token(self, token: str, verify_exp: bool = True) -> dict | None:
        """Decode and validate a JWT token.
        
        Args:
            token: JWT token to decode
            verify_exp: Whether to verify expiration time
            
        Returns:
            Decoded payload or None if invalid
        """
        try:
            # Decode the token
            payload = jwt_decode(
                token=token,
                key=self._secret_key,
                algorithms=[self._algorithm],
                options={"verify_exp": verify_exp},
            )
            return payload
        except ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except JWTError as e:
            logger.error(f"Failed to decode token: {str(e)}")
            return None
    
    def _add_standard_claims(self, payload: dict) -> None:
        """Add standard JWT claims to a payload.
        
        Args:
            payload: Dictionary to add claims to
        """
        # Set the issued at time if not present
        if "iat" not in payload:
            payload["iat"] = datetime.now(timezone.utc)
            
        # Add audience if configured
        if self._token_audience and "aud" not in payload:
            payload["aud"] = self._token_audience
            
        # Add issuer if configured
        if self._token_issuer and "iss" not in payload:
            payload["iss"] = self._token_issuer
        
    async def create_access_token(
        self,
        user_id: str | UUID,
        roles: list[str] | None = None,
        expires_delta_minutes: int | None = None,
        additional_claims: dict | None = None,
    ) -> str:
        """Create a JWT access token for authentication.

        Args:
            user_id: The user ID to encode in the token
            roles: The user roles to encode in the token
            expires_delta_minutes: Custom expiration time in minutes
            additional_claims: Optional additional claims to include in the token

        Returns:
            JWT access token as a string
        """
        try:
            # Handle case where user_id is a dictionary with sub key (from tests)
            if isinstance(user_id, dict) and "sub" in user_id:
                user_id_str = str(user_id["sub"])
                # If roles not explicitly provided but in the dict, use those
                if roles is None and "roles" in user_id:
                    roles = user_id["roles"]
                # Add all other keys as additional claims
                if additional_claims is None:
                    additional_claims = {}
                for key, value in user_id.items():
                    if key not in ["sub", "roles"] and key not in additional_claims:
                        additional_claims[key] = value
            else:
                # Convert the user_id to a string if it's a UUID
                user_id_str = str(user_id)

            # Create token with standard claims
            payload = {
                "sub": user_id_str,
                "type": "access",  # Token type for validation
                "jti": str(uuid4()),  # Unique token ID for blacklisting
            }

            # Add roles if provided
            if roles:
                payload["roles"] = roles

            # Add any additional claims
            if additional_claims:
                for key, value in additional_claims.items():
                    # Don't override existing claims
                    if key not in payload:
                        payload[key] = value

            # Set the expiration time
            if expires_delta_minutes is not None:
                expires_delta = timedelta(minutes=expires_delta_minutes)
            elif "expires_delta" in payload and isinstance(payload["expires_delta"], timedelta):
                # Handle case where expires_delta is provided in additional_claims
                expires_delta = payload.pop("expires_delta")
            else:
                # Default to 15 minutes for access tokens if settings available
                access_minutes = self._access_token_expire_minutes
                expires_delta = timedelta(minutes=access_minutes)

            expire = datetime.now(timezone.utc) + expires_delta
            payload["exp"] = int(expire.timestamp())

            # Add standard token fields
            self._add_standard_claims(payload)

            # Log token creation (without including the actual token)
            logger.info(f"Access token created for user {user_id_str}")

            # Audit the token creation if logger is available
            if self.audit_logger:
                await self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_CREATED,
                    user_id=user_id_str,
                    description="Access token created",
                    metadata={
                        "token_type": "access",
                        "expires_at": expire.isoformat(),
                        "roles": str(roles) if roles else "none",
                    },
                )

            # Encode the token
            return await self._encode_token(payload)
        except Exception as e:
            # Log the error (with sensitive info removed)
            logger.error(f"Error creating access token: {str(e)}")
            # Re-raise with a sanitized message (no PHI)
            raise JWTError(f"Could not create token: {type(e).__name__}") from e

    async def create_refresh_token(
        self,
        user_id: str | UUID,

    Args:
        user_id: The user ID to encode in the token
        expires_delta_minutes: Custom expiration time in minutes
        family_id: Optional family ID to group related refresh tokens
        additional_claims: Optional additional claims to include in the token

    Returns:
        JWT refresh token as a string
    """
    try:
        # Handle case where user_id is a dictionary with sub key (from tests)
        if isinstance(user_id, dict) and "sub" in user_id:
            user_id_str = str(user_id["sub"])
            # If additional_claims not explicitly provided but in the dict, use those
            if additional_claims is None:
                additional_claims = {}
            for key, value in user_id.items():
                if key != "sub" and key not in additional_claims:
                    additional_claims[key] = value
        else:
            # Convert the user_id to a string if it's a UUID
            user_id_str = str(user_id)

        # Generate a unique family ID for this token if not provided
        token_family_id = family_id if family_id else str(uuid4())

        # Create token with standard claims plus the family_id
        payload = {
            "sub": user_id_str,
            "type": "refresh",  # Token type for validation
            "family_id": token_family_id,  # Group related refresh tokens
            "jti": str(uuid4()),  # Unique token ID for blacklisting
        }

        # Handle the case where family_id is provided in additional_claims
        if additional_claims and "family_id" in additional_claims and not family_id:
            token_family_id = additional_claims["family_id"]
            payload["family_id"] = token_family_id

        # Add additional claims (excluding family_id which is already handled)
        if additional_claims:
            for key, value in additional_claims.items():
                if key != "family_id" and key not in payload:  # Don't override existing claims
                    payload[key] = value

        # Set the expiration time
        if expires_delta_minutes is not None:
            expires_delta = timedelta(minutes=expires_delta_minutes)
        else:
            # Default to 7 days for refresh tokens if settings available
            refresh_days = self.settings.REFRESH_TOKEN_EXPIRE_DAYS if self.settings else 7
            expires_delta = timedelta(days=refresh_days)

        expire = datetime.now(timezone.utc) + expires_delta
        payload["exp"] = expire

        # Add standard token fields
        self._add_standard_claims(payload)

        # Log token creation (without including the actual token)
        logger.info(
            f"Refresh token created for user {user_id_str} with family_id {token_family_id}"
        )

        # Audit the token creation
        self.audit_logger.log_security_event(
            AuditEventType.TOKEN_CREATED,
            user_id=user_id_str,
            details={
                "token_type": "refresh",
                "family_id": token_family_id,
                "expires_at": expire.isoformat(),
            },
        )

        # Encode the token
        return self._encode_token(payload)
    except Exception as e:
        # Log the error (with sensitive info removed)
        logger.error(f"Error creating refresh token: {str(e)}")
        raise


async def revoke_token(self, token: str) -> bool:
    """Revoke a token by adding it to the blacklist.

    Args:
        token: The token to revoke

    Returns:
        True if token was successfully revoked, False otherwise
    """
    try:
        # Initialize the token blacklist dictionary if it doesn't exist
        if not hasattr(self, "_token_blacklist") or self._token_blacklist is None:
            self._token_blacklist = {}

        # For testing purposes, decode token without verifying audience
        options = {"verify_aud": False}

        # Decode token to get the JTI claim - don't verify expiration for revocation
        try:
            payload = self._decode_token(token, verify_exp=False, options=options)
        except (JWTError, ExpiredSignatureError) as e:
            logger.error(f"Error decoding token for revocation: {str(e)}")
            # Even if token is expired, we should still try to blacklist it
            # Use a relaxed decode approach for blacklisting
            try:
                payload = jwt_decode(
                    token,
                    self._secret_key,
                    options={"verify_signature": True, "verify_exp": False, "verify_aud": False},
                )
            except Exception as inner_err:
                logger.error(f"Error during token revocation: {str(inner_err)}")
                return False

        if not payload or "jti" not in payload:
            logger.warning("Cannot revoke token: missing jti claim")
            return False

        # Extract the JTI claim
        jti = payload["jti"]

        # Add to blacklist with expiration time
        if "exp" in payload:
            expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        else:
            # Default to 24 hours if no expiration in token
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        # Add token to blacklist
        self._token_blacklist[jti] = {
            "expires_at": expires_at,
            "revoked_at": datetime.now(timezone.utc),
        }

        # Log the blacklisting (without including the actual token)
        logger.info(f"Token {jti} added to blacklist")

        # Audit the token revocation
        user_id = payload.get("sub", "unknown")
        self.audit_logger.log_security_event(
            AuditEventType.TOKEN_REVOKED,
            user_id=str(user_id),
            details={
                "token_type": payload.get("type", "unknown"),
                "jti": jti,
            },
        )

        return True
    except Exception as e:
        logger.error(f"Error during token revocation: {str(e)}")
        return False


async def decode_token(self, token: str, options: dict | None = None) -> Any:
    """
    Decode a JWT token and return its payload.

    This method is used by authentication services to extract token data.

    Args:
        token: The JWT token to decode
        options: Optional dictionary of decode options to pass to jose.jwt.decode

    Returns:
        Token payload data

    Raises:
        JWTError: If token is invalid or malformed
    """
    try:
        # Use the internal decode method
        decode_options = options or {}
        payload = self._decode_token(token, options=decode_options)
        if not payload:
            raise JWTError("Invalid token payload")

        # Audit successful token decoding (without exposing sensitive data)
        self.audit_logger.log_security_event(
            AuditEventType.TOKEN_VALIDATION,
            user_id=str(payload.get("sub", "unknown")),
            details={
                "token_type": payload.get("type", "unknown"),
                "jti": payload.get("jti", "unknown"),
            },
        )

        return payload
    except ExpiredSignatureError:
        # Audit failed validation due to expiration
        self.audit_logger.log_security_event(
            AuditEventType.TOKEN_VALIDATION_FAILED,
            details={"reason": "Token expired"},
        )
        raise TokenExpiredException("Token has expired")
    except JWTError as e:
        # Audit failed validation
        self.audit_logger.log_security_event(
            AuditEventType.TOKEN_VALIDATION_FAILED,
            details={"reason": str(e)},
        )
        raise InvalidTokenException(f"Failed to decode token: {str(e)}")


def _decode_token(
    self, token: str, verify_exp: bool = True, options: dict | None = None
) -> dict[str, Any]:
    """Internal method to decode a JWT token and return the raw claims dictionary.

    Args:
        token: The JWT token to decode
        verify_exp: Whether to verify expiration claim
        options: Optional dictionary of decode options

    Returns:
        Dictionary containing token claims

    Raises:
        InvalidTokenException: If token is invalid
        TokenExpiredException: If token has expired
    """
    try:
        # For security, we always verify the signature
        decode_options = {
            "verify_signature": True,
            "verify_exp": verify_exp,
            "verify_aud": True,  # Default to verifying audience
        }

        # Update with any user-provided options
        if options:
            decode_options.update(options)

        # Decode the token
        return jwt_decode(
            token,
            self._secret_key,
            algorithms=[self._algorithm],
            options=decode_options,
            audience=self._token_audience,
            issuer=self._token_issuer,
        )
    except ExpiredSignatureError as e:
        logger.warning(f"Token expired: {str(e)}")
        raise TokenExpiredException("Token has expired") from e
    except JWTError as e:
        logger.warning(f"Invalid token: {str(e)}")
        raise InvalidTokenException(f"Invalid token: {str(e)}") from e
