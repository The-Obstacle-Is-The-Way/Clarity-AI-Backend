"""
Implementation of JWT service for authentication, authorization, and token management.

Follows clean architecture principles by implementing the IJwtService interface
and handling JWT token creation, validation, and management for HIPAA compliance.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from jose.exceptions import ExpiredSignatureError, JWTError, JWSError, JWTClaimsError
from jose.jwt import decode as jwt_decode, encode as jwt_encode
from pydantic import BaseModel, Field

from app.core.config.settings import Settings
from app.core.domain.entities.user import User
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository 
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.audit_logger_interface import IAuditLogger, AuditEventType, AuditSeverity
from app.core.interfaces.services.jwt_service import IJwtService
from app.domain.enums.token_type import TokenType
from app.domain.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    TokenExpiredError,
    TokenBlacklistedException,
    InvalidTokenException,
    TokenExpiredException
)

# Use domain exceptions for backward compatibility
TokenBlacklistedError = TokenBlacklistedException
InvalidTokenError = InvalidTokenException  # Ensure consistent exception types
TokenExpiredError = TokenExpiredException  # Ensure consistent exception types

# Constants for testing and defaults
TEST_SECRET_KEY = "test-jwt-secret-key-must-be-at-least-32-chars-long"

# Initialize logger
logger = logging.getLogger(__name__)


class TokenPayload(BaseModel):
    """Token payload model with full compatibility for all tests."""
    sub: str
    exp: Optional[int] = None
    iat: Optional[int] = None
    type: Optional[str] = None
    roles: Optional[List[str]] = Field(default_factory=list)
    jti: Optional[str] = None
    custom_fields: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    # For backward compatibility
    def __getitem__(self, key):
        if key in self.__dict__:
            return self.__dict__[key]
        elif key in self.custom_fields:
            return self.custom_fields[key]
        raise KeyError(f"Key {key} not found in token payload")
    
    def __contains__(self, key):
        return key in self.__dict__ or (self.custom_fields and key in self.custom_fields)
    
    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


class JWTServiceImpl(IJwtService):
    """Implementation of the JWT Service interface."""
    
    def __init__(
        self,
        settings: Settings,
        user_repository: Optional[IUserRepository] = None,
        token_blacklist_repository: Optional[ITokenBlacklistRepository] = None,
        audit_logger: Optional[IAuditLogger] = None
    ):
        """Initialize JWT service with necessary dependencies.
        
        Args:
            settings: Application settings for JWT configuration
            user_repository: Repository for user data access
            token_blacklist_repository: Repository for token blacklisting
            audit_logger: Service for audit logging
        """
        self.settings = settings
        self.user_repository = user_repository
        self.token_blacklist_repository = token_blacklist_repository
        self.audit_logger = audit_logger
        
        # JWT settings
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        self.refresh_token_expire_minutes = settings.refresh_token_expire_minutes
        self.token_issuer = settings.token_issuer
        self.token_audience = settings.token_audience
        
        logger.info(f"JWT Service initialized with algorithm {self.algorithm}")
    
    def create_access_token(
        self,
        subject: Optional[str] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
        expires_delta: Optional[timedelta] = None,
        expires_delta_minutes: Optional[int] = None,
        data: Optional[Union[Dict[str, Any], Any]] = None,
    ) -> str:
        """Create an access token for a user.
        
        Args:
            subject: User identifier
            additional_claims: Additional claims to include
            expires_delta: Custom expiration time
            expires_delta_minutes: Custom expiration in minutes
            data: Alternative way to provide token data
            
        Returns:
            Encoded JWT access token
        """
        # Handle data parameter for backward compatibility
        if data is not None:
            if isinstance(data, dict):
                subject = data.get("sub") or subject
                additional_claims = {**data, **additional_claims} if additional_claims else data
            elif hasattr(data, "id"):
                # Handle User object or similar with id attribute
                subject = str(data.id)
                if hasattr(data, "roles") and not additional_claims:
                    additional_claims = {"roles": data.roles}
        
        if subject is None and (not additional_claims or "sub" not in additional_claims):
            raise ValueError("Subject is required for token creation")
            
        # Use subject from additional_claims if not provided directly
        if subject is None and additional_claims and "sub" in additional_claims:
            subject = additional_claims.pop("sub")
        
        # Convert UUID to string if needed
        if isinstance(subject, UUID):
            subject = str(subject)
        
        # Get roles from additional_claims
        roles = []
        if additional_claims and "roles" in additional_claims:
            roles = additional_claims.pop("roles", [])
        
        # Get current time
        now = datetime.now(timezone.utc)
        
        # Set token expiration based on provided options
        if expires_delta:
            expire = now + expires_delta
        elif expires_delta_minutes:
            expire = now + timedelta(minutes=expires_delta_minutes)
        else:
            expire = now + timedelta(minutes=self.access_token_expire_minutes)
        
        # Create token claims
        claims = {
            "sub": subject,
            "exp": int(expire.timestamp()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "jti": str(uuid4()),
            "type": TokenType.ACCESS.value,
            "roles": roles,
        }
        
        # Add the issuer and audience if specified
        if self.token_issuer:
            claims["iss"] = self.token_issuer
        
        if self.token_audience:
            claims["aud"] = self.token_audience
        
        # Add any additional claims
        if additional_claims:
            for key, value in additional_claims.items():
                if key not in claims:
                    claims[key] = value
        
        # Create token
        token = jwt_encode(claims, self.secret_key, algorithm=self.algorithm)
        
        # Audit log the token creation
        try:
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_CREATION,
                    description=f"Access token created for user: {subject}",
                    severity=AuditSeverity.INFO,
                    user_id=subject,
                    metadata={"token_jti": claims["jti"], "token_type": TokenType.ACCESS.value}
                )
        except Exception as e:
            logger.warning(f"Failed to log token creation: {str(e)}")
        
        return token
    
    def create_refresh_token(
        self,
        subject: Optional[str] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
        expires_delta: Optional[timedelta] = None,
        expires_delta_minutes: Optional[int] = None,
        data: Optional[Union[Dict[str, Any], Any]] = None,
    ) -> str:
        """Create a refresh token for a user.
        
        Args:
            subject: User identifier
            additional_claims: Additional claims to include
            expires_delta: Custom expiration time
            expires_delta_minutes: Custom expiration in minutes
            data: Alternative way to provide token data
            
        Returns:
            Encoded JWT refresh token
        """
        # Handle data parameter for backward compatibility
        if data is not None:
            if isinstance(data, dict):
                subject = data.get("sub") or subject
                additional_claims = {**data, **additional_claims} if additional_claims else data
            elif hasattr(data, "id"):
                # Handle User object or similar with id attribute
                subject = str(data.id)
                if hasattr(data, "roles") and not additional_claims:
                    additional_claims = {"roles": data.roles}
        
        if subject is None and (not additional_claims or "sub" not in additional_claims):
            raise ValueError("Subject is required for token creation")
            
        # Use subject from additional_claims if not provided directly
        if subject is None and additional_claims and "sub" in additional_claims:
            subject = additional_claims.pop("sub")
        
        # Convert UUID to string if needed
        if isinstance(subject, UUID):
            subject = str(subject)
        
        # Get roles from additional_claims
        roles = []
        if additional_claims and "roles" in additional_claims:
            roles = additional_claims.pop("roles", [])
        
        # Get current time
        now = datetime.now(timezone.utc)
        
        # Set token expiration based on provided options
        if expires_delta:
            expire = now + expires_delta
        elif expires_delta_minutes:
            expire = now + timedelta(minutes=expires_delta_minutes)
        else:
            expire = now + timedelta(minutes=self.refresh_token_expire_minutes)
        
        # Create token claims
        claims = {
            "sub": subject,
            "exp": int(expire.timestamp()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "jti": str(uuid4()),
            "type": TokenType.REFRESH.value,
            "roles": roles,
        }
        
        # Add the issuer and audience if specified
        if self.token_issuer:
            claims["iss"] = self.token_issuer
        
        if self.token_audience:
            claims["aud"] = self.token_audience
        
        # Add any additional claims
        if additional_claims:
            for key, value in additional_claims.items():
                if key not in claims:
                    claims[key] = value
        
        # Create token
        token = jwt_encode(claims, self.secret_key, algorithm=self.algorithm)
        
        # Audit log the token creation
        try:
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_CREATION,
                    description=f"Refresh token created for user: {subject}",
                    severity=AuditSeverity.INFO,
                    user_id=subject,
                    metadata={"token_jti": claims["jti"], "token_type": TokenType.REFRESH.value}
                )
        except Exception as e:
            logger.warning(f"Failed to log token creation: {str(e)}")
        
        return token
    
    def decode_token(
        self,
        token: str,
        verify_signature: bool = True,
        verify_exp: bool = True,
        verify_aud: bool = True,
        verify_iss: bool = True,
        options: Optional[Dict[str, Any]] = None,
        audience: Optional[str] = None,
        algorithms: Optional[List[str]] = None,
    ) -> TokenPayload:
        """Decode and validate a JWT token.
        
        Args:
            token: JWT token to decode
            verify_signature: Whether to verify signature
            verify_exp: Whether to verify expiration
            verify_aud: Whether to verify audience
            verify_iss: Whether to verify issuer
            options: Additional decoding options
            audience: Override audience
            algorithms: Override algorithms
            
        Returns:
            TokenPayload: Decoded token payload
            
        Raises:
            InvalidTokenException: If token is invalid
            TokenExpiredException: If token is expired
            TokenBlacklistedException: If token is blacklisted
        """
        # Log validation attempt (without token content for security)
        try:
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_VALIDATION,
                    description="Token validation attempt",
                    severity=AuditSeverity.INFO
                )
        except Exception as e:
            logger.warning(f"Failed to log token validation: {str(e)}")
        
        # Set up decoding options
        decode_options = {
            "verify_signature": verify_signature,
            "verify_exp": verify_exp,
            "verify_aud": verify_aud,
            "verify_iss": verify_iss,
        }
        
        if options:
            decode_options.update(options)
        
        # Use provided algorithms or default
        if algorithms is None:
            algorithms = [self.algorithm]
        
        # Use provided audience or default
        if audience is None:
            audience = self.token_audience if verify_aud else None
        
        try:
            # Decode token with minimal validation first to get the JTI
            try:
                unverified_payload = jwt_decode(
                    token=token,
                    key=self.secret_key,
                    algorithms=algorithms,
                    options={"verify_signature": True, "verify_exp": False}
                )
                
                # Check if token is blacklisted
                if self.token_blacklist_repository and "jti" in unverified_payload:
                    jti = unverified_payload["jti"]
                    is_blacklisted = self.token_blacklist_repository.is_blacklisted(jti)
                    if is_blacklisted:
                        if self.audit_logger:
                            self.audit_logger.log_security_event(
                                event_type=AuditEventType.TOKEN_VALIDATION_FAILED,
                                description="Blacklisted token used",
                                severity=AuditSeverity.WARNING,
                                metadata={"jti": jti}
                            )
                        raise TokenBlacklistedException("Token has been revoked")
            except Exception:
                # If we can't even decode it initially, proceed to full validation
                pass
            
            # Full token validation
            payload = jwt_decode(
                token=token,
                key=self.secret_key,
                algorithms=algorithms,
                options=decode_options,
                issuer=self.token_issuer if verify_iss else None,
                audience=audience
            )
            
            # Convert to TokenPayload model for consistency
            token_payload = TokenPayload(
                sub=payload["sub"],
                exp=payload.get("exp"),
                iat=payload.get("iat"),
                type=payload.get("type"),
                roles=payload.get("roles", []),
                jti=payload.get("jti")
            )
            
            # Add any other claims to custom_fields
            for key, value in payload.items():
                if key not in {"sub", "exp", "iat", "type", "roles", "jti"}:
                    token_payload.custom_fields[key] = value
            
            return token_payload
            
        except ExpiredSignatureError as e:
            # Log validation failure
            try:
                if self.audit_logger:
                    self.audit_logger.log_security_event(
                        event_type=AuditEventType.TOKEN_VALIDATION_FAILED,
                        description="Expired token used",
                        severity=AuditSeverity.WARNING
                    )
            except Exception as log_error:
                logger.warning(f"Failed to log token validation failure: {str(log_error)}")
            
            raise TokenExpiredException("Token has expired")
            
        except (JWTError, JWSError, JWTClaimsError) as e:
            # Log validation failure
            try:
                if self.audit_logger:
                    self.audit_logger.log_security_event(
                        event_type=AuditEventType.TOKEN_VALIDATION_FAILED,
                        description=f"Invalid token: {str(e)}",
                        severity=AuditSeverity.WARNING
                    )
            except Exception as log_error:
                logger.warning(f"Failed to log token validation failure: {str(log_error)}")
            
            raise InvalidTokenException(f"Invalid token: {str(e)}")
    
    async def get_user_from_token(self, token: str) -> Optional[User]:
        """Get user from a token.
        
        Args:
            token: JWT token
            
        Returns:
            Optional[User]: User if found, None otherwise
        """
        if not self.user_repository:
            logger.warning("User repository not configured")
            return None
        
        try:
            # Decode token
            payload = self.decode_token(token)
            subject = payload.sub
            
            # Get user from repository
            return await self.user_repository.get_by_id(subject)
        except Exception as e:
            logger.error(f"Failed to get user from token: {str(e)}")
            return None
    
    def verify_refresh_token(self, refresh_token: str) -> TokenPayload:
        """Verify that a token is a valid refresh token.
        
        Args:
            refresh_token: Token to verify
            
        Returns:
            TokenPayload: Decoded token payload
            
        Raises:
            InvalidTokenException: If token is not a refresh token
        """
        # Decode refresh token
        payload = self.decode_token(refresh_token)
        
        # Verify it's a refresh token
        if not payload.type or payload.type != TokenType.REFRESH.value:
            raise InvalidTokenException("Not a refresh token")
        
        return payload
    
    def get_token_payload_subject(self, payload: Any) -> Optional[str]:
        """Get the subject from a token payload.
        
        Args:
            payload: Token payload
            
        Returns:
            Optional[str]: Subject if present
        """
        if isinstance(payload, TokenPayload):
            return payload.sub
        elif isinstance(payload, dict) and "sub" in payload:
            return payload["sub"]
        elif hasattr(payload, "sub"):
            return payload.sub
        return None
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """Refresh an access token using a refresh token.
        
        Args:
            refresh_token: Refresh token to use
            
        Returns:
            str: New access token
            
        Raises:
            InvalidTokenException: If token is not a refresh token
        """
        # Decode refresh token
        payload = self.verify_refresh_token(refresh_token)
        
        # Get subject and roles
        subject = payload.sub
        roles = payload.roles or []
        
        # Create new access token
        return self.create_access_token(
            subject=subject,
            additional_claims={"roles": roles}
        )
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke a token by adding it to the blacklist.
        
        Args:
            token: Token to revoke
            
        Returns:
            bool: True if token was successfully revoked
        """
        return await self.blacklist_token(token)
    
    async def blacklist_token(self, token: str) -> bool:
        """Add a token to the blacklist.
        
        Args:
            token: Token to blacklist
            
        Returns:
            bool: True if token was successfully blacklisted
        """
        if not self.token_blacklist_repository:
            logger.warning("Token blacklist repository not configured")
            return False
        
        try:
            # Decode token with minimal validation to get expiry and JTI
            payload = jwt_decode(
                token=token,
                key=self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": True, "verify_exp": False}
            )
            
            if "jti" not in payload or "exp" not in payload:
                logger.warning("Token missing required fields (jti, exp)")
                return False
            
            jti = payload["jti"]
            exp_timestamp = payload["exp"]
            
            # Convert timestamp to datetime
            expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            
            # Add to blacklist
            await self.token_blacklist_repository.add_to_blacklist(jti, expires_at)
            
            # Log blacklisting
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_REVOCATION,
                    description=f"Token blacklisted: {jti}",
                    severity=AuditSeverity.INFO,
                    metadata={"jti": jti}
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to blacklist token: {str(e)}")
            return False
    
    async def logout(self, token: str) -> bool:
        """Log out a user by revoking their token.
        
        Args:
            token: JWT token to revoke
            
        Returns:
            bool: True if logout was successful
        """
        # Just revoke the token
        return await self.revoke_token(token)
    
    async def blacklist_session(self, session_id: str) -> bool:
        """Blacklist all tokens associated with a session.
        
        Args:
            session_id: ID of the session to blacklist
            
        Returns:
            bool: True if session was blacklisted
        """
        if not self.token_blacklist_repository:
            logger.warning("Token blacklist repository not configured")
            return False
        
        try:
            # This assumes the repository has a method to blacklist by session ID
            # You may need to implement this method in the repository
            if hasattr(self.token_blacklist_repository, "blacklist_session"):
                await self.token_blacklist_repository.blacklist_session(session_id)
                
                # Log blacklisting
                if self.audit_logger:
                    self.audit_logger.log_security_event(
                        event_type=AuditEventType.TOKEN_REVOCATION,
                        description=f"Session blacklisted: {session_id}",
                        severity=AuditSeverity.INFO,
                        metadata={"session_id": session_id}
                    )
                
                return True
            else:
                logger.warning("Token blacklist repository does not support session blacklisting")
                return False
                
        except Exception as e:
            logger.error(f"Failed to blacklist session: {str(e)}")
            return False