"""
JWT (JSON Web Token) Service for authentication.

This service handles token creation, validation, and management according to
HIPAA security standards and best practices for healthcare applications.
"""

import json
import logging
import re
import time
import uuid
from uuid import uuid4
from datetime import datetime, timedelta, timezone, date
from enum import Enum
from typing import Any, Optional, Union, cast

# Replace direct jose import with our adapter
try:
    from app.infrastructure.security.jwt.jose_adapter import (
        ExpiredSignatureError,
        JWTError,
    )
    from app.infrastructure.security.jwt.jose_adapter import decode as jwt_decode
    from app.infrastructure.security.jwt.jose_adapter import encode as jwt_encode
except ImportError:
    # Fallback to direct imports if adapter is not available
    from jose import jwt as jose_jwt
    from jose.exceptions import ExpiredSignatureError, JWTError, JWTClaimsError

    def jwt_encode(claims: dict[str, Any], key: str, algorithm: str, **kwargs: Any) -> str:
        return jose_jwt.encode(claims, key, algorithm=algorithm, **kwargs)

    def jwt_decode(token: str, key: str, algorithms: list[str] = None, options: dict[str, Any] = None, **kwargs: Any) -> dict[str, Any]:
        return jose_jwt.decode(token, key, algorithms=algorithms, options=options, **kwargs)

from pydantic import BaseModel, ValidationError, computed_field

# Import interfaces and domain models
from app.core.interfaces.services.jwt_service import IJwtService

# Import domain exceptions
try:
    from app.domain.exceptions import (
        AuthenticationError,
        InvalidTokenError, 
        TokenExpiredError
    )
except ImportError:
    # Define fallbacks if imports fail
    class AuthenticationError(Exception):
        """Authentication failed."""
        pass
        
    class InvalidTokenError(Exception):
        """Invalid token exception."""
        pass
        
    class TokenExpiredError(Exception):
        """Token expired exception."""
        pass

# Import token type enum
try:
    from app.domain.enums.token_type import TokenType
except ImportError:
    # Fallback when enum module doesn't exist (for local testing)
    class TokenType(str, Enum):
        """Token types used in the application."""

        ACCESS = "access"
        REFRESH = "refresh"
        RESET = "reset"  # For password reset
        ACTIVATE = "activate"  # For account activation
        API = "api"  # For long-lived API tokens with restricted permissions


# Import user entity
try:
    from app.domain.entities.user import User
except ImportError:
    # Fallback if User cannot be imported
    User = Any

# Import exceptions
try:
    from app.domain.exceptions import AuthenticationError
except ImportError:
    # Define a fallback
    class AuthenticationError(Exception):
        """Authentication Error."""

        pass


# Import core interfaces  - following Clean Architecture principles
try:
    from app.core.interfaces.repositories.token_blacklist_repository_interface import (
        ITokenBlacklistRepository,
    )
    from app.core.interfaces.repositories.user_repository_interface import IUserRepository
    from app.core.interfaces.services.audit_logger_interface import IAuditLogger
    from app.core.config.settings import Settings
except ImportError:
    # Fallback for imports during testing
    from app.domain.repositories.token_blacklist_repository_interface import (
        ITokenBlacklistRepository,
    )
    from app.domain.repositories.user_repository_interface import IUserRepository
    
    # Import IAuditLogger from core interfaces first
    try:
        from app.core.interfaces.services.audit_logger_interface import IAuditLogger
    except ImportError:
        # Fallback for audit logger interface
        from abc import ABC, abstractmethod
        class IAuditLogger(ABC):
            """Stub interface for audit logging during testing."""
            @abstractmethod
            def log_security_event(self, event_type: str, description: str | None = None, 
                                user_id: str | None = None, actor_id: str | None = None, 
                                severity: str | None = None, details: dict | None = None, 
                                status: str | None = None, metadata: dict | None = None, 
                                ip_address: str | None = None) -> None:
                """Log security events."""
                pass
            
    # Fallback Settings class for testing
    class Settings:
        """Stub Settings class for testing."""
        JWT_SECRET_KEY = None
        ENVIRONMENT = "test"


# Import necessary exceptions from domain layer
try:
    from app.core.exceptions.auth import (
        InvalidTokenError,
        RevokedTokenException,
        TokenBlacklistedException,
        TokenGenerationException,
        TokenExpiredError,
        TokenDecodingException,
    )
    from app.core.constants.audit import AuditEventType, AuditSeverity
except ImportError:
    # Fallback for imports during testing
    class InvalidTokenError(Exception):
        """Invalid token exception."""
        pass
        
    class RevokedTokenError(Exception):
        """Revoked token exception."""
        pass
        
    class TokenBlacklistedError(Exception):
        """Token blacklisted exception."""
        pass
        
    class TokenGenerationError(Exception):
        """Token generation exception."""
        pass
        
    class TokenExpiredError(Exception):
        """Token expired exception."""
        pass
        
    class TokenDecodingError(Exception):
        """Token decoding exception."""
        pass
    
    # Define fallback constants for testing
    class AuditEventType:
        """Audit event types for security events."""
        TOKEN_CREATED = "token_created"
        TOKEN_VALIDATED = "token_validated"
        TOKEN_REJECTED = "token_rejected"
        TOKEN_REVOKED = "token_revoked"
    
    class AuditSeverity:
        """Severity constants for audit logging."""
        INFO = "info"
        WARNING = "warning"
        ERROR = "error"


# Logging setup
try:
    from app.core.interfaces.services.audit_logger_interface import IAuditLogger
    from app.infrastructure.logging.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback for imports during testing
    import logging
    logger = logging.getLogger(__name__)


class TokenPayload(BaseModel):
    """Token payload model for validation.

    JWT claims spec: https://tools.ietf.org/html/rfc7519#section-4.1
    """

    # Required JWT claims (RFC 7519)
    iss: str | None = None  # Issuer
    sub: str | None = None  # Subject
    aud: str | list | None = None  # Audience
    exp: int | None = None  # Expiration time
    nbf: int | None = None  # Not Before time
    iat: int | None = None  # Issued At time
    jti: str | None = None  # JWT ID

    # Custom claims
    type: str | None = None  # Token type ("access", "refresh")
    refresh: bool = False  # Is this a refresh token
    scope: str | None = None  # Token scope
    roles: list[str] = []  # User roles

    # Organization and project context
    org_id: str | None = None  # Organization ID
    org_name: str | None = None  # Organization name
    project_id: str | None = None  # Project ID
    family_id: str | None = None  # Token family ID (for refresh tokens)
    
    # Allow attribute access to facilitate token family ID retrieval
    def __getattr__(self, name):
        if name == "fid" and "family_id" in self.__dict__:
            return self.__dict__["family_id"]
        return super().__getattr__(name)

    def is_expired(self) -> bool:
        """Check if the token is expired."""
        try:
            now = datetime.now(timezone.utc).timestamp()
            return now > float(self.exp)
        except Exception as e:
            logging.warning(f"Error checking token expiration: {e}")
            return True  # Default to expired for safety

    def get_expiration(self) -> datetime:
        """Get the token expiration as a datetime object."""
        return datetime.fromtimestamp(self.exp, tz=timezone.utc)


# Define token types
class TokenType(str, Enum):
    """Token types used in the application."""
    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"  # For password reset
    ACTIVATE = "activate"  # For account activation
    API = "api"  # For long-lived API tokens


# Type definition for token blacklist dictionary
TokenBlacklistDict = dict[str, Union[datetime, float, str]]


class JWTService(IJwtService):
    """JWT Service implementation.
    
    This service handles JWT token generation, validation, and management for
    authentication and authorization purposes in HIPAA-compliant environments.
    """
    
    # Define audit event types for security events
    TOKEN_CREATED = "token_created"
    TOKEN_VALIDATED = "token_validated"
    TOKEN_REJECTED = "token_rejected"
    TOKEN_REVOKED = "token_revoked"
    
    def is_expired(self, token: str) -> bool:
        """Check if the token is expired."""
        try:
            payload = self._decode_jwt(
                token, self.secret_key, algorithms=[self.algorithm]
            )
            exp = payload.get("exp")
            if not exp:
                return True

            now = datetime.now(timezone.utc).timestamp()
            result = bool(now > float(exp))  # Explicit cast to bool
            return result
        except Exception as e:
            logging.warning(f"Error checking token expiration: {e}")
            return True  # Default to expired for safety

    def __init__(
        self,
        settings: Any = None,
        token_blacklist_repository: Optional[ITokenBlacklistRepository] = None,
        user_repository: Any = None,
        audit_logger: Optional[IAuditLogger] = None,
        secret_key: Optional[str] = None,
        algorithm: Optional[str] = None,
        access_token_expire_minutes: Optional[int] = None,
        refresh_token_expire_days: Optional[int] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
    ):
        """
        Initialize JWT service with configuration.

        Args:
            settings: Application settings
            token_blacklist_repository: Repository for blacklisted tokens
            user_repository: Repository to fetch user details (optional, needed for get_user_from_token)
            audit_logger: Service for audit logging of security events
            secret_key: Override JWT secret key
            algorithm: Override JWT algorithm
            access_token_expire_minutes: Override access token expiration
            refresh_token_expire_days: Override refresh token expiration
            issuer: Override JWT issuer
            audience: Override JWT audience
        """
        self.token_blacklist_repository = token_blacklist_repository
        self.settings = settings
        self.user_repository = user_repository
        self.audit_logger = audit_logger

        # Get secret key from parameters or settings
        if secret_key:
            self.secret_key = secret_key
        elif settings and hasattr(settings, "JWT_SECRET_KEY") and settings.JWT_SECRET_KEY:
            # Extract string value from SecretStr if needed
            if hasattr(settings.JWT_SECRET_KEY, "get_secret_value"):
                self.secret_key = settings.JWT_SECRET_KEY.get_secret_value()
            else:
                self.secret_key = str(settings.JWT_SECRET_KEY)
        else:
            # Use a default for testing if in test environment
            if settings and hasattr(settings, "ENVIRONMENT") and settings.ENVIRONMENT == "test":
                self.secret_key = "testsecretkeythatisverylong"
            else:
                raise ValueError("JWT_SECRET_KEY is required in settings")

        # Get algorithm from parameters or settings with default
        self.algorithm = algorithm or getattr(settings, "JWT_ALGORITHM", "HS256")

        # Get token expiration times with defaults for testing
        self.access_token_expire_minutes = access_token_expire_minutes or getattr(
            settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 30
        )
        self.refresh_token_expire_days = refresh_token_expire_days or getattr(
            settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7
        )

        # Get optional issuer and audience
        self.issuer = issuer or getattr(settings, "JWT_ISSUER", None)
        self.audience = audience or getattr(settings, "JWT_AUDIENCE", None)

        # Initialize token blacklist
        self.token_blacklist_repository: ITokenBlacklistRepository = token_blacklist_repository
        
        if self.token_blacklist_repository is None:
            logger.warning("No token blacklist repository provided. Using in-memory blacklist, which is NOT suitable for production.")
            
        # Initialize audit logger
        self.audit_logger: IAuditLogger | None = audit_logger
        if self.audit_logger is None:
            logger.warning("No audit logger provided. Security events will not be properly logged for HIPAA compliance.")
            
        # Token family tracking for refresh token rotation
        # Maps family_id -> latest_jti to detect refresh token reuse
        self._token_families: dict[str, str] = {}
        
        logging.info(f"JWT service initialized with algorithm {self.algorithm}")

    def _make_payload_serializable(self, payload: dict) -> dict:
        """Convert payload values to JSON-serializable types."""
        import enum

        result = {}
        for k, v in payload.items():
            if isinstance(v, uuid.UUID):
                result[k] = str(v)
            elif isinstance(v, datetime | date):  # Use union syntax for isinstance
                result[k] = v.isoformat()
            elif isinstance(v, enum.Enum):
                result[k] = v.value
            elif isinstance(v, dict):
                result[k] = self._make_payload_serializable(v)
            elif isinstance(v, list):
                # Split complex list comprehension across multiple lines for readability
                serialized_list = []
                for i in v:
                    if isinstance(i, dict):
                        serialized_list.append(self._make_payload_serializable(i))
                    elif isinstance(i, uuid.UUID):
                        serialized_list.append(str(i))
                    else:
                        serialized_list.append(i)
                result[k] = serialized_list
            else:
                result[k] = v
        return result

    def create_access_token(
        self,
        data: dict[str, Any],
        subject: Optional[str] = None,
        expires_delta: Optional[timedelta] = None,
        expires_delta_minutes: Optional[int] = None,
        additional_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Create a new access token for a user.

        Args:
            data: Dictionary containing claims, including 'sub' for subject
            subject: Subject identifier (typically the user ID) if not in data
            expires_delta: Custom expiration time
            expires_delta_minutes: Custom expiration time in minutes
            additional_claims: Custom claims to include in the token

        Returns:
            Encoded JWT access token

        Raises:
            ValueError: If neither data with 'sub' nor subject is provided
        """
        # Initialize claims dict and extract subject
        effective_claims = {}
        if data:
            effective_claims.update(data)
        if additional_claims:
            effective_claims.update(additional_claims)
            
        # Extract subject from data or use provided subject
        effective_subject = subject
        if not effective_subject and data and "sub" in data:
            effective_subject = data["sub"]
        elif not effective_subject and data and "user_id" in data:
            effective_subject = data["user_id"]
            
        # Validate we have a subject
        if not effective_subject:
            raise ValueError("Subject (user ID) is required in data or as a parameter")
            
        # Ensure sub claim is set
        effective_claims["sub"] = effective_subject

        # Create a unique ID for this token
        token_jti = str(uuid.uuid4())

        # Create the token using the internal method
        token = self._create_jwt(
            subject=effective_subject,
            expires_delta_minutes=expires_delta_minutes,
            expires_delta=expires_delta,
            token_type="access",
            jti=token_jti,
            additional_claims=effective_claims,
        )

        # Log the security event
        if self.audit_logger:
            self.audit_logger.log_security_event(
                event_type=self.TOKEN_CREATED,
                description="Access token created",
                user_id=effective_subject,
                severity=AuditSeverity.INFO,
                metadata={"jti": token_jti, "expires_at": str(datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes))}
            )

    def create_refresh_token(
        self,
        data: dict[str, Any],
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """
        Create a new refresh token for a user.

        Args:
            data: Dictionary containing claims, including 'sub' for subject
            expires_delta: Custom expiration time

        Returns:
            str: JWT refresh token
        """
        # Extract subject from data
        subject = data.get('sub')
        if not subject:
            raise ValueError("Subject is required for token creation")
            
        # Use standard JWT expiration if none provided
        if expires_delta is None:
            expires_delta = timedelta(days=self.refresh_token_expire_days)
            
        # Generate a token JTI
        token_jti = str(uuid4())
        
        # Add standard claims
        to_encode = data.copy()
        to_encode.update({
            "jti": token_jti,
            "exp": int((datetime.now(timezone.utc) + expires_delta).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "type": "refresh",
            "refresh": True
        })
        
        # Add issuer and audience if available
        if self.issuer:
            to_encode["iss"] = self.issuer
        if self.audience:
            to_encode["aud"] = self.audience
            
        # Create JWT token
        try:
            encoded_jwt = jwt_encode(
                to_encode, self.secret_key, algorithm=self.algorithm
            )
            
            # Log token creation
            logger.info(f"Created refresh token for subject {subject[:8] if subject else 'unknown'}...")
            
            # Log security event
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_CREATED,
                    description="Refresh token created",
                    user_id=subject,
                    severity=AuditSeverity.INFO,
                    metadata={"jti": token_jti}
                )
                
            # Track token family if applicable
            family_id = to_encode.get("family")
            if family_id:
                self._token_families[family_id] = token_jti
                
            return encoded_jwt
        except Exception as e:
            logger.error(f"Error creating refresh token: {e}")
            raise TokenDecodingError(f"Failed to create token: {e}") from e

    async def refresh_token(self, refresh_token: str) -> str:
        """
        Create a new refresh token using a valid refresh token.

        This is used to implement refresh token rotation. The old token is
        revoked and a new one is issued with the same claims but a new expiration
        time and JTI.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New refresh token

        Raises:
            InvalidTokenError: If the refresh token is invalid
            TokenExpiredError: If the refresh token is expired
            TokenBlacklistedException: If the refresh token has been blacklisted
        """
        try:
            # Decode the refresh token
            payload = self.decode_token(
                token=refresh_token,
                options={"verify_signature": True, "verify_exp": True},
            )
            
            # Verify this is a refresh token
            if not self._is_refresh_token(payload):
                raise InvalidTokenError("Not a refresh token")
                
            # Check if token is blacklisted
            jti = payload.get("jti")
            if jti and await self._is_token_blacklisted(jti):
                raise TokenBlacklistedException("Token has been blacklisted")
                
            # Get the token family for security
            token_family = payload.get("family")
            if not token_family:
                # For tokens without a family, create a new one
                token_family = str(uuid4())
            
            # Get claims to preserve
            sub = payload.get("sub")
            claims = {}
            for claim in self.preserved_claims:
                if claim in payload and claim not in self.exclude_from_refresh:
                    claims[claim] = payload[claim]
            
            # Update the reference claim to point to the old token
            claims["ref"] = jti
            claims["family"] = token_family
            claims["sub"] = sub  # Ensure subject is in the data dictionary
            
            # Blacklist the old token
            await self.revoke_token(refresh_token)
            
            # Return a new refresh token
            return self.create_refresh_token(data=claims)
            
        except Exception as e:
            # Log the error
            logger.error(f"Error refreshing token: {e}")
            # Re-raise the specific error
            raise

    def _is_refresh_token(self, payload: dict) -> bool:
        """Check if a token is a refresh token based on its payload.
        
        Args:
            payload: Token payload
            
        Returns:
            bool: True if the token is a refresh token
        """
        return payload.get("refresh", False)

# Define dependency injection function
def get_jwt_service(
    settings: Settings, user_repository=None, token_blacklist_repository=None
) -> JWTService:
    """
    Factory function to create a JWTService with the correct configuration.

    This function ensures that the JWTService is created with appropriate settings
    for the current environment, including handling SecretStr for the JWT secret key.

    Args:
        settings: Application settings object
        user_repository: Optional repository for user data
        token_blacklist_repository: Optional repository for token blacklisting

    Returns:
        Configured JWTService instance

    Raises:
        ValueError: If required settings are missing or invalid
    """
    if not settings:
        raise ValueError("Settings object is required")

    # Extract and validate JWT secret key
    if not hasattr(settings, "JWT_SECRET_KEY") or not settings.JWT_SECRET_KEY:
        # Use a default for testing if in test environment
        if hasattr(settings, "ENVIRONMENT") and settings.ENVIRONMENT == "test":
            secret_key = "testsecretkeythatisverylong"
        else:
            raise ValueError("JWT_SECRET_KEY is required in settings")
    else:
        # Handle SecretStr type safely
        if hasattr(settings.JWT_SECRET_KEY, "get_secret_value"):
            secret_key = settings.JWT_SECRET_KEY.get_secret_value()
        else:
            secret_key = str(settings.JWT_SECRET_KEY)

    # Validate secret key
    if not secret_key or len(secret_key.strip()) < 16:
        if hasattr(settings, "ENVIRONMENT") and settings.ENVIRONMENT == "test":
            # Allow shorter keys in test
            if len(secret_key.strip()) < 8:
                secret_key = "testsecretkeythatisverylong"
        else:
            raise ValueError("JWT_SECRET_KEY must be at least 16 characters long")

    # Get required settings with validation
    try:
        algorithm = str(getattr(settings, "JWT_ALGORITHM", "HS256"))
        if algorithm not in ["HS256", "HS384", "HS512"]:
            raise ValueError(f"Unsupported JWT algorithm: {algorithm}")

        access_token_expire_minutes = int(getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 30))
        if access_token_expire_minutes < 1:
            raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES must be positive")

        refresh_token_expire_days = int(getattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7))
        if refresh_token_expire_days < 1:
            raise ValueError("JWT_REFRESH_TOKEN_EXPIRE_DAYS must be positive")

    except (ValueError, TypeError) as e:
        if hasattr(settings, "ENVIRONMENT") and settings.ENVIRONMENT == "test":
            # Use defaults in test environment
            algorithm = "HS256"
            access_token_expire_minutes = 30
            refresh_token_expire_days = 7
        else:
            raise ValueError(f"Invalid JWT settings: {e!s}")

    # Get optional settings
    issuer = getattr(settings, "JWT_ISSUER", None)
    audience = getattr(settings, "JWT_AUDIENCE", None)

    # Create and return a JWTService instance with validated settings
    return JWTService(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
        token_blacklist_repository=token_blacklist_repository,
        user_repository=user_repository,
        issuer=issuer,
        audience=audience,
        settings=settings,
    )
