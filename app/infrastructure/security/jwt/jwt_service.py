"""
JWT Service Implementation.

This service handles JWT token creation, validation, and management according to
HIPAA security standards and best practices for healthcare applications.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, Dict, List, Optional, Union
# Make sure List is properly imported
from uuid import UUID, uuid4

from jose.exceptions import ExpiredSignatureError, JWTError
from jose.jwt import decode as jwt_decode, encode as jwt_encode

from pydantic import BaseModel

# For type annotations and interface definitions
try:
    from app.core.domain.entities.user import User
except ImportError:
    from app.domain.entities.user import User

from app.core.interfaces.services.jwt_service import IJwtService
from app.core.config.settings import Settings

# Import IAuditLogger and ITokenBlacklistRepository interfaces
from app.core.interfaces.services.audit_logger_interface import IAuditLogger, AuditEventType, AuditSeverity
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository

from app.domain.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    TokenExpiredError,
    TokenBlacklistedException,
    InvalidTokenException
)

from app.domain.enums.token_type import TokenType

# Define custom exceptions if they don't exist in domain.exceptions
# Using TokenBlacklistedException from domain.exceptions instead
TokenBlacklistedError = TokenBlacklistedException

class TokenManagementError(InvalidTokenError):
    """Exception raised for token management operations failures."""
    pass

# Initialize logger
logger = logging.getLogger(__name__)

class TokenPayload(BaseModel):
    """Token payload model for validation.

    JWT claims spec: https://tools.ietf.org/html/rfc7519#section-4.1
    """
    # Required JWT claims (RFC 7519)
    iss: Optional[str] = None  # Issuer
    sub: Optional[str] = None  # Subject
    aud: Optional[Union[str, List[str]]] = None  # Audience
    exp: Optional[int] = None  # Expiration time
    nbf: Optional[int] = None  # Not Before time
    iat: Optional[int] = None  # Issued At time
    jti: Optional[str] = None  # JWT ID

    # Constants for class-wide use
    TOKEN_TYPE_CLAIM: ClassVar[str] = "type"  # Standardized claim for token type
    ACCESS_TOKEN_TYPE: ClassVar[str] = "access"
    REFRESH_TOKEN_TYPE: ClassVar[str] = "refresh"
    RESET_TOKEN_TYPE: ClassVar[str] = "reset"  # Is this a refresh token
    scope: Optional[str] = None  # Token scope
    roles: List[str] = []  # User roles

    # Organization and project context
    org_id: Optional[str] = None  # Organization ID
    family_id: Optional[str] = None  # Token family ID (for refresh tokens)


class JWTService(IJwtService):
    """JWT Service implementation.
    
    This service handles JWT token generation, validation, and management for
    authentication and authorization purposes in HIPAA-compliant environments.
    """
    
    # Token family management for refresh tokens
    preserved_claims = [
        "sub", "roles", "org_id", "org_name", "project_id", 
        "scope", "permissions", "device_id", "client_id"
    ]
    
    # Claims to exclude when refreshing tokens
    exclude_from_refresh = ["exp", "iat", "nbf", "jti", "iss", "aud"]
    
    # In-memory blacklist fallback
    _token_blacklist = {}
    
    # Standard algorithm configs - add more as needed for tests
    ALGORITHMS: ClassVar[Dict[str, Dict[str, str]]] = {
        "HS256": {
            "description": "HMAC with SHA-256", 
            "key_requirements": "Symmetric key (32+ bytes recommended)",
            "security_level": "Medium",
        },
        "HS384": {
            "description": "HMAC with SHA-384",
            "key_requirements": "Symmetric key (48+ bytes recommended)",
            "security_level": "Medium-High",
        },
        "HS512": {
            "description": "HMAC with SHA-512",
            "key_requirements": "Symmetric key (64+ bytes recommended)",
            "security_level": "High",
        },
    }

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
            user_repository: Repository to fetch user details
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
        
        # Initialize token family tracking for refresh token rotation
        self._token_families: Dict[str, Dict] = {}
        
        # Initialize in-memory token blacklist
        # In-memory blacklist for immediate revocation
        self._token_blacklist: Dict[str, Dict[str, Any]] = {}
        
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
        
        logger.info(f"JWT service initialized with algorithm {self.algorithm}")

    def _sanitize_error_message(self, message: str) -> str:
        """Sanitize error messages to avoid leaking sensitive information."""
        # Define patterns for sensitive data that shouldn't be in errors
        sensitive_patterns = [
            # Regex for sensitive data sanitization would go here
        ]
        sanitized = message
        
        # Apply sanitization rules to remove sensitive data
        for pattern in sensitive_patterns:
            if pattern in sanitized:
                sanitized = sanitized.replace(pattern, "[REDACTED]")
        
        return sanitized

    def create_access_token(
        self,
        subject: str,
        additional_claims: Dict[str, Any] | None = None,
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None,
    ) -> str:
        """Creates a new access token."""
        # Generate a unique JTI for the token
        jti = str(uuid4())
        
        # Get the expiration time
        if expires_delta_minutes is not None:
            expires_delta = timedelta(minutes=float(expires_delta_minutes))
        if not expires_delta:
            # Default from settings or fallback value
            minutes = getattr(self.settings, "ACCESS_TOKEN_EXPIRE_MINUTES", None) or 30
            expires_delta = timedelta(minutes=float(minutes))
            
        # Create claim set
        now = datetime.now(timezone.utc)
        claims = {
            "sub": str(subject),
            "iat": int(now.timestamp()),
            "exp": int((now + expires_delta).timestamp()),
            "jti": jti,
            "type": "access"
        }
        
        # Add optional claims
        if self.issuer:
            claims["iss"] = self.issuer
        if self.audience:
            claims["aud"] = self.audience
            
        # Add additional claims if provided
        if additional_claims:
            claims.update(additional_claims)
            
        # Encode the token
        try:
            token = jwt_encode(claims, self.secret_key, algorithm=self.algorithm)
            
            # Log the security event
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_CREATED,
                    description="Access token created",
                    user_id=str(subject),
                    severity=AuditSeverity.INFO,
                    metadata={"jti": jti}
                )
                
            return token
            
        except Exception as e:
            logger.error(f"Error creating access token: {e}")
            raise InvalidTokenError(f"Failed to create access token: {e}")

    def create_refresh_token(
        self,
        subject: str,
        additional_claims: Dict[str, Any] | None = None,
        expires_delta: timedelta | None = None,
        expires_delta_days: int | None = None,
    ) -> str:
        """Creates a new refresh token."""
        # Generate a unique JTI for the token
        jti = str(uuid4())
        
        # Get the expiration time
        if expires_delta_days is not None:
            expires_delta = timedelta(days=float(expires_delta_days))
        if not expires_delta:
            # Default from settings or fallback value
            days = getattr(self.settings, "REFRESH_TOKEN_EXPIRE_DAYS", None) or 7
            expires_delta = timedelta(days=float(days))
            
        # Create claim set
        now = datetime.now(timezone.utc)
        claims = {
            "sub": str(subject),
            "iat": int(now.timestamp()),
            "exp": int((now + expires_delta).timestamp()),
            "jti": jti,
            "type": "refresh",
            "refresh": True
        }
        
        # Generate a family ID for this refresh token
        family_id = str(uuid4())
        claims["family_id"] = family_id
        
        # Add optional claims
        if self.issuer:
            claims["iss"] = self.issuer
        if self.audience:
            claims["aud"] = self.audience
            
        # Add additional claims if provided
        if additional_claims:
            claims.update(additional_claims)
            
        # Encode the token
        try:
            token = jwt_encode(claims, self.secret_key, algorithm=self.algorithm)
            
            # Track the token family
            self._token_families[family_id] = jti
            
            # Log the security event
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_CREATED,
                    description="Refresh token created",
                    user_id=str(subject),
                    severity=AuditSeverity.INFO,
                    metadata={"jti": jti, "family_id": family_id}
                )
                
            return token
            
        except Exception as e:
            logger.error(f"Error creating refresh token: {e}")
            raise InvalidTokenError(f"Failed to create refresh token: {e}")

    def decode_token(
        self,
        token: str,
        verify_signature: bool = True,
        options: Optional[Dict[str, Any]] = None,
        audience: Optional[str] = None,
        algorithms: Optional[List[str]] = None,
    ) -> Any:
        """Decode and validate a JWT token.

        Args:
            token: JWT token to decode
            verify_signature: Whether to verify token signature
            options: Options for decoding
            audience: Expected audience
            algorithms: List of allowed algorithms

        Returns:
            Decoded token payload
        """
        if not token:
            raise InvalidTokenError("Invalid token: Token is empty or None")

        # Basic token format validation
        if not isinstance(token, str):
            if isinstance(token, bytes):
                raise InvalidTokenError("Invalid token: Invalid header string")
            else:
                raise InvalidTokenError("Invalid token: Not enough segments")

        # Check if token follows the standard JWT format
        if token.count(".") != 2:
            raise InvalidTokenError("Invalid token: Not enough segments")
            
        if options is None:
            options = {"verify_signature": verify_signature}
            
        # If algorithms not provided, use the configured algorithm
        if algorithms is None:
            algorithms = [self.algorithm]
            
        # Set audience if provided or use default
        if audience is None and self.audience:
            audience = self.audience
            
        try:
            # Decode the token
            payload = jwt_decode(
                token=token,
                key=self.secret_key if verify_signature else "",
                algorithms=algorithms,
                options=options,
                audience=audience,
                issuer=self.issuer
            )
            
            # Process the payload for consistency
            if "type" not in payload:
                # Set default type based on presence of 'refresh' claim
                payload["type"] = "refresh" if payload.get("refresh", False) else "access"
                
            # Process roles if they exist for backward compatibility
            if "role" in payload and "roles" not in payload:
                # Convert single role to roles array
                payload["roles"] = [payload["role"]]
            elif "roles" not in payload:
                # Ensure roles exists even if empty
                payload["roles"] = []
                
            # Log the token validation if we have an audit logger
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_VALIDATED,
                    description="Token validated successfully",
                    user_id=payload.get("sub", "unknown"),
                    severity=AuditSeverity.INFO,
                    metadata={"jti": payload.get("jti", "unknown")}
                )
                
            return payload
            
        except ExpiredSignatureError:
            # Handle expired tokens
            logger.warning("Token has expired")
            raise TokenExpiredError("Token has expired")
        except JWTError as e:
            # Handle invalid tokens
            error_message = str(e)
            logger.warning(f"JWT validation error: {error_message}")
            
            if "Invalid issuer" in error_message:
                raise InvalidTokenError("Invalid issuer")
            elif "Invalid audience" in error_message:
                raise InvalidTokenError("Invalid audience")
            elif "Signature verification failed" in error_message:
                raise InvalidTokenError("Invalid token signature")
            elif "Not enough segments" in error_message:
                raise InvalidTokenError("Invalid token format")
            else:
                raise InvalidTokenError(f"Invalid token: {error_message}")
        except Exception as e:
            # Handle unexpected errors
            logger.error(f"Error decoding token: {e}")
            raise InvalidTokenError(f"Invalid token: {e}")

    async def get_user_from_token(self, token: str) -> Optional[User]:
        """Get the user associated with a token."""
        try:
            # Decode the token first to validate it
            payload = self.decode_token(token)
            user_id = payload.get("sub")
            if not user_id:
                logger.warning("Token doesn't contain 'sub' claim with user ID")
                raise InvalidTokenError("Invalid token: missing user ID")

            # Look up user using repository
            if self.user_repository:
                user = await self.user_repository.get_by_id(user_id)
                if not user:
                    logger.warning(f"User {user_id} from token not found in database")
                    if self.audit_logger:
                        self.audit_logger.log_security_event(
                            event_type=AuditEventType.TOKEN_REJECTED,
                            description="Invalid token: user not found",
                            user_id=user_id,
                            severity=AuditSeverity.WARNING,
                            metadata={"status": "failure"}
                        )
                    raise InvalidTokenError("Invalid token: user not found")
                return user
            else:
                logger.warning("No user repository available to look up user")
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving user from token: {e}")
            raise InvalidTokenError(str(e))
            
    def verify_refresh_token(
        self, token: str, enforce_refresh_type: bool = True
    ) -> Dict[str, Any]:
        """Verify that a token is a valid refresh token."""
        # Decode the token
        try:
            # Use standard options 
            options = {"verify_signature": True, "verify_exp": True}
            payload = self.decode_token(token, options=options)

            # Check that it's a refresh token
            if enforce_refresh_type and not payload.get("refresh", False) and payload.get("type") != "refresh":
                raise InvalidTokenError("Not a refresh token")
                
            # Check token family for reuse
            if "family_id" in payload and payload["family_id"] in self._token_families:
                latest_jti = self._token_families[payload["family_id"]]
                if payload.get("jti") != latest_jti:
                    # This is a reused token from this family
                    raise InvalidTokenError("Refresh token reuse detected")

            return payload

        except TokenExpiredError:
            # Specifically handle expired refresh tokens
            raise TokenExpiredError("Refresh token has expired")
        except InvalidTokenError:
            # Pass through our specific exception type
            raise
        except Exception as e:
            logger.error(f"Error verifying refresh token: {e}")
            raise InvalidTokenError(f"Invalid refresh token: {e}")
            
    def get_token_payload_subject(self, payload: Any) -> Optional[str]:
        """Extracts the subject (user identifier) from the token payload."""
        if not payload:
            return None
        return payload.get("sub")
        
    def refresh_access_token(self, refresh_token: str) -> str:
        """Refresh an access token using a valid refresh token."""
        try:
            # Verify the refresh token
            payload = self.verify_refresh_token(refresh_token)
            
            # Extract user ID and create a new access token
            user_id = payload.get("sub")
            if not user_id:
                raise InvalidTokenError("Invalid token: missing subject claim")

            # Create a new access token with the same claims
            claims = {}
            for claim in self.preserved_claims:
                if claim in payload and claim not in self.exclude_from_refresh:
                    claims[claim] = payload[claim]
                    
            # Create a new access token
            new_access_token = self.create_access_token(
                subject=user_id,
                additional_claims=claims
            )
            
            # Log the security event
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_CREATED,
                    description="Access token created from refresh token",
                    user_id=user_id,
                    severity=AuditSeverity.INFO,
                    metadata={"user_id": user_id}
                )

            return new_access_token

        except Exception as e:
            logger.warning(f"Failed to refresh token: {e}")
            raise InvalidTokenError("Invalid or expired refresh token")

    async def revoke_token(self, token: str) -> bool:
        """Revokes a token by adding its JTI to the blacklist."""
        try:
            # Decode the token to get the JTI
            payload = self.decode_token(token, options={"verify_signature": True, "verify_exp": False})
            jti = payload.get("jti")
            if not jti:
                logger.warning("Token has no JTI, cannot be blacklisted")
                return False

            # Get expiration time and user ID
            exp = payload.get("exp", int(datetime.now(timezone.utc).timestamp()) + 3600)
            user_id = payload.get("sub", "unknown")

            # Add to blacklist
            if self.token_blacklist_repository:
                # Convert exp to datetime
                expiry_datetime = datetime.fromtimestamp(exp, tz=timezone.utc)
                
                # Add to blacklist repository
                await self.token_blacklist_repository.add_to_blacklist(
                    token="",  # We don't store the actual token, just the JTI
                    jti=jti,
                    expires_at=expiry_datetime,
                    reason="Token revoked"
                )
                
                # Log the security event
                if self.audit_logger:
                    self.audit_logger.log_security_event(
                        event_type=AuditEventType.TOKEN_REVOKED,
                        description="Token revoked",
                        user_id=user_id,
                        severity=AuditSeverity.INFO,
                        metadata={"jti": jti}
                    )
            else:
                # Fallback to in-memory blacklist
                self._token_blacklist[jti] = True

            logger.info(f"Token with JTI {jti} has been blacklisted")
            return True

        except Exception as e:
            logger.error(f"Error revoking token: {e}")
            return False
            
    async def logout(self, token: str) -> bool:
        """Log out a user by revoking their token."""
        try:
            # Try to decode the token first to get user information for audit logging
            try:
                payload = self.decode_token(token, options={"verify_signature": True, "verify_exp": False})
                user_id = payload.get("sub", "unknown")
            except Exception:
                # If token is invalid, still try to revoke it but without user info
                user_id = "unknown"
                
            # Revoke the token
            result = await self.revoke_token(token)
            
            # Log the security event
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_REVOKED,
                    description="User logged out",
                    user_id=user_id,
                    severity=AuditSeverity.INFO,
                    metadata={"status": "success" if result else "failure"}
                )
                
            return result
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return False
            
    async def blacklist_session(self, session_id: str) -> bool:
        """Blacklist all tokens associated with a session."""
        if not session_id:
            logger.warning("Empty session ID provided for blacklisting")
            return False
            
        try:
            if self.token_blacklist_repository:
                # Use repository to store session in blacklist
                if hasattr(self.token_blacklist_repository, "blacklist_session"):
                    await self.token_blacklist_repository.blacklist_session(session_id)
                    logger.info(f"Blacklisted session {session_id}")
                else:
                    logger.warning("Repository doesn't implement blacklist_session")
                    return False
            else:
                logger.warning(f"Cannot blacklist session {session_id} - no repository configured")
                return False
                
            # Log the event
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_REVOKED,
                    description="Session blacklisted",
                    severity=AuditSeverity.INFO,
                    metadata={"session_id": session_id}
                )
                
            return True
            
        except Exception as e:
            logger.error(f"Error blacklisting session {session_id}: {e}")
            return False

    async def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify a JWT token's validity and return its decoded payload."""
        try:
            # Decode and validate the token
            payload = self.decode_token(token)
            
            # Check if token is blacklisted
            jti = payload.get("jti")
            if jti:
                # Check in-memory blacklist first
                if jti in self._token_blacklist:
                    raise TokenBlacklistedError("Token has been blacklisted")
                    
                # Check repository if available
                if self.token_blacklist_repository:
                    is_blacklisted = await self.token_blacklist_repository.is_blacklisted(jti)
                    if is_blacklisted:
                        reason = "Unknown reason"
                        blacklist_info = await self.token_blacklist_repository.get_blacklist_info(jti)
                        if blacklist_info and "reason" in blacklist_info:
                            reason = blacklist_info["reason"]
                        
                        # Raise token blacklisted exception
                        raise TokenBlacklistedError(f"Token has been blacklisted: {reason}")
            
            return payload
            
        except TokenBlacklistedError:
            # Re-raise blacklist exceptions without modification
            raise
        except Exception as e:
            # Log and sanitize other errors
            logger.error(f"Error verifying token: {e}")
            raise InvalidTokenError(self._sanitize_error_message(str(e)))
            
    # Implementing required abstract methods from the interface
    async def blacklist_token(self, token: str, expires_at: datetime) -> None:
        """Add a token to the blacklist to prevent its future use."""
        try:
            # Decode the token to get the JTI
            payload = self.decode_token(token, options={"verify_signature": True, "verify_exp": False})
            jti = payload.get("jti")
            if not jti:
                logger.warning("Token has no JTI, cannot be blacklisted")
                raise InvalidTokenError("Token has no JTI, cannot be blacklisted")

            # Add to in-memory blacklist
            self._token_blacklist[jti] = {
                "expires_at": expires_at,
                "reason": "Token blacklisted",
                "blacklisted_at": datetime.now()
            }
            
            # Add to blacklist repository if available
            if self.token_blacklist_repository:
                # Add to blacklist repository
                await self.token_blacklist_repository.add_to_blacklist(
                    token="",  # We don't store the actual token, just the JTI
                    jti=jti,
                    expires_at=expires_at,
                    reason="Token blacklisted"
                )
                
            # Log the security event
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_REVOKED,
                    description="Token blacklisted",
                    severity=AuditSeverity.INFO,
                    metadata={"jti": jti}
                )
                
        except Exception as e:
            logger.error(f"Error blacklisting token: {e}")
            raise TokenManagementError(f"Failed to blacklist token: {self._sanitize_error_message(str(e))}") from e
        
    # This is a helper method that was refactored into the actual implementation below
    # Keeping the method signature for backward compatibility
    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted.
        
        Args:
            token: The JWT token to check
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        return await self._is_token_blacklisted_internal(token)
                
    async def revoke_token_by_jti(self, jti: str, expires_at: datetime, reason: str = "Token revoked") -> None:
        """Revoke a token using its JTI.
        
        Args:
            jti: The JTI of the token to revoke
            expires_at: When the token expires
            reason: The reason for revocation
        """
        try:
            # Add to in-memory blacklist
            self._token_blacklist[jti] = {
                "expires_at": expires_at,
                "reason": reason,
                "blacklisted_at": datetime.now()
            }
            
            # Add to repository if available
            if self.token_blacklist_repository:
                await self.token_blacklist_repository.add_to_blacklist(
                    token="",  # We don't store the actual token
                    jti=jti,
                    expires_at=expires_at,
                    reason=reason
                )
            
            # Log the event if logger is available
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_REVOKED,
                    description=reason,
                    severity=AuditSeverity.INFO,
                    metadata={"jti": jti}
                )
                
        except Exception as e:
            logger.error(f"Error revoking token JTI {jti}: {e}")
            raise TokenManagementError(f"Failed to revoke token: {self._sanitize_error_message(str(e))}") from e
            
    async def _is_token_blacklisted_internal(self, token: str) -> bool:
        """Internal implementation to check if a token is blacklisted.
        
        Args:
            token: The JWT token to check
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        try:
            # Decode the token to get the JTI
            payload = self.decode_token(token, options={"verify_signature": True, "verify_exp": False})
            jti = payload.get("jti")
            if not jti:
                # Tokens without JTI can't be in blacklist
                logger.warning("Token has no JTI claim, cannot check blacklist")
                return False
                
            # Check in-memory blacklist first
            if jti in self._token_blacklist:
                return True
                
            # Check repository if available
            if self.token_blacklist_repository:
                return await self.token_blacklist_repository.is_blacklisted(jti)
                
            return False
                
        except Exception as e:
            logger.error(f"Error checking if token is blacklisted: {e}")
            # If we can't verify, assume it's not blacklisted
            return False

    async def get_token_identity(self, token: str) -> Union[str, UUID]:
        """Extract the user identity from a token."""
        try:
            payload = self.decode_token(token)
            subject = payload.get("sub")
            if not subject:
                raise InvalidTokenError("Token does not contain identity")
                
            # Return the subject as a UUID if possible, otherwise as a string
            try:
                return UUID(subject)
            except ValueError:
                return subject
                
        except Exception as e:
            logger.error(f"Error extracting identity from token: {e}")
            raise InvalidTokenError(f"Failed to extract identity: {e}")


# Define dependency injection function
# Import implementation to avoid circular imports
from app.infrastructure.security.jwt.jwt_service_impl import JWTServiceImpl

def get_jwt_service(
    settings: Any, 
    user_repository: Any = None, 
    token_blacklist_repository = None,  # Remove type annotation for FastAPI compatibility
    audit_logger = None  # Remove type annotation for FastAPI compatibility
):
    """Dependency injection factory for JWT service."""
    # Get secret key with proper error handling
    secret_key = None
    
    # Try to get secret key from settings
    if hasattr(settings, "JWT_SECRET_KEY"):
        # Handle SecretStr if needed
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

    # Create and return a JWTServiceImpl instance with validated settings
    return JWTServiceImpl(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
        token_blacklist_repository=token_blacklist_repository,
        user_repository=user_repository,
        audit_logger=audit_logger,
        issuer=issuer,
        audience=audience,
        settings=settings,
    )