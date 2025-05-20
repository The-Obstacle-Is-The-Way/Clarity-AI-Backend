"""
JWT Service module.

This module provides a service for JWT token generation, validation, and management,
following HIPAA compliance requirements for secure authentication and authorization.
"""

import asyncio
import time
import uuid
from datetime import timedelta
from typing import Any

import jwt
from pydantic import BaseModel

from app.core.config import Settings
from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.core.interfaces.repositories.token_repository_interface import ITokenRepository
from app.core.interfaces.services.audit_logger_interface import (
    AuditEventType,
    AuditSeverity,
    IAuditLogger,
)
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.utils.date_utils import utcnow
from app.domain.exceptions.auth_exceptions import (
    InvalidTokenException,
    TokenBlacklistedException,
    TokenExpiredException,
)


class TokenPayload(BaseModel):
    """Model representing the payload of a JWT token."""

    sub: str  # Subject (user ID)
    exp: int  # Expiration time
    iat: int  # Issued at
    jti: str  # JWT ID (unique identifier for this token)
    session_id: str  # Session ID
    user_id: str  # User ID
    email: str  # User email
    role: str  # User role
    permissions: list[str]  # User permissions
    token_type: str  # Token type


class JWTService(IJwtService):
    """
    Service for JWT token generation, validation, and management.

    This service adheres to HIPAA security requirements for authentication
    and authorization, including:
    - Secure token generation with appropriate expiration
    - Token validation and verification
    - Token blacklisting to enforce logout
    - Audit logging of token-related activities
    """

    def __init__(
        self,
        token_repo: ITokenRepository,
        blacklist_repo: ITokenBlacklistRepository,
        audit_logger: IAuditLogger,
    ):
        """
        Initialize the JWT service.

        Args:
            token_repo: Repository for managing tokens
            blacklist_repo: Repository for managing blacklisted tokens
            audit_logger: Service for audit logging
        """
        self.token_repo = token_repo
        self.blacklist_repo = blacklist_repo
        self.audit_logger = audit_logger
        self.algorithm = "HS256"  # HMAC with SHA-256

        # Validate that we have required secrets
        if not self.settings.jwt_secret_key:
            raise ValueError("JWT_SECRET_KEY is required")

    def create_access_token(
        self,
        data: dict[str, Any],
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None,
    ) -> str:
        """
        Creates a new access token.
        
        Args:
            data: Dictionary containing token data (user_id, email, role, permissions, session_id)
            expires_delta: Optional custom expiration time
            expires_delta_minutes: Optional custom expiration time in minutes
            
        Returns:
            The encoded JWT token string
        """
        # Extract data from dictionary
        user_id = data.get("user_id") or data.get("sub")
        email = data.get("email", "")
        role = data.get("role", "")
        permissions = data.get("permissions", [])
        session_id = data.get("session_id", str(uuid.uuid4()))
        
        if not user_id:
            raise ValueError("user_id or sub is required in data dictionary")
        """
        # Calculate expiration time
        if expires_delta is None:
            if expires_delta_minutes is not None:
                expires_delta = timedelta(minutes=expires_delta_minutes)
            else:
                expires_delta = timedelta(minutes=self.settings.access_token_expire_minutes)
        
        expire = utcnow() + expires_delta
        expires_in = int(expires_delta.total_seconds())

        # Create token ID
        token_id = str(uuid.uuid4())

        # Create payload
        payload = {
            "sub": user_id,
            "exp": int(expire.timestamp()),
            "iat": int(utcnow().timestamp()),
            "jti": token_id,
            "session_id": session_id,
            "user_id": user_id,
            "email": email,
            "role": role,
            "permissions": permissions,
        }

        # Create token
        access_token = jwt.encode(payload, self.settings.jwt_secret_key, algorithm=self.algorithm)

        # Log token creation
        self.audit_logger.log_security_event(
            event_type="TOKEN_CREATED",
            user_id=user_id,
            description=f"Access token created for user {email}",
            metadata={
                "token_id": token_id,
                "session_id": session_id,
                "expires_at": expire.isoformat(),
            },
        )

        # For compatibility with existing code that expects a tuple
        if hasattr(self, "_return_expires_in") and self._return_expires_in:
            return access_token, expires_in
            
        return access_token

    def create_refresh_token(
        self,
        data: dict[str, Any],
        expires_delta: timedelta | None = None,
        expires_delta_minutes: int | None = None,
    ) -> str:
        """
        Creates a new refresh token.
        
        Args:
            data: Dictionary containing token data (user_id, email, session_id)
            expires_delta: Optional custom expiration time
            expires_delta_minutes: Optional custom expiration time in minutes
            
        Returns:
            The encoded JWT refresh token string
        """
        # Extract data from dictionary
        user_id = data.get("user_id") or data.get("sub")
        email = data.get("email", "")
        session_id = data.get("session_id", str(uuid.uuid4()))
        
        if not user_id:
            raise ValueError("user_id or sub is required in data dictionary")

        # Calculate expiration time
        expires_delta = timedelta(days=self.settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        expire = utcnow() + expires_delta

        # Create token ID
        token_id = str(uuid.uuid4())

        # Create payload
        payload = {
            "sub": user_id,
            "exp": int(expire.timestamp()),
            "iat": int(utcnow().timestamp()),
            "jti": token_id,
            "session_id": session_id,
            "user_id": user_id,
            "email": email,
            "token_type": "refresh",
        }

        # Create token
        refresh_token = jwt.encode(payload, self.settings.jwt_secret_key, algorithm=self.algorithm)

        # Log token creation
        self.audit_logger.log_security_event(
            event_type="REFRESH_TOKEN_CREATED",
            user_id=user_id,
            description=f"Refresh token created for user {email}",
            metadata={
                "token_id": token_id,
                "session_id": session_id,
                "expires_at": expire.isoformat(),
            },
        )

        return refresh_token

    def decode_token(self, token: str, token_type: str = "access") -> TokenPayload:
        """
        Validate a JWT token and return its payload.

        Args:
            token: The token to validate
            token_type: The type of token ('access' or 'refresh')

        Returns:
            The decoded token payload

        Raises:
            InvalidTokenException: If the token is invalid
            TokenExpiredException: If the token has expired
            TokenBlacklistedException: If the token is blacklisted
        """
        try:
            payload = jwt.decode(token, self.settings.jwt_secret_key, algorithms=[self.algorithm])
            token_payload = TokenPayload(**payload)

            # Check if token is blacklisted using JTI
            jti = token_payload.jti
            if asyncio.run(self.blacklist_repo.is_jti_blacklisted(jti)):
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_VALIDATION_FAILURE,
                    user_id=token_payload.user_id,
                    description=f"{token_type.capitalize()} token validation failed: token is blacklisted",
                    severity=AuditSeverity.HIGH,
                    metadata={"jti": jti, "token_type": token_type},
                )
                raise TokenBlacklistedException(f"{token_type.capitalize()} token is blacklisted.")

            # Verify expiration
            if token_payload.exp < time.time():
                self.audit_logger.log_security_event(
                    event_type=AuditEventType.TOKEN_VALIDATION_FAILURE,
                    user_id=token_payload.user_id,
                    description=f"{token_type.capitalize()} token validation failed: token has expired",
                    severity=AuditSeverity.HIGH,
                    metadata={"jti": jti, "token_type": token_type},
                )
                raise TokenExpiredException(f"{token_type.capitalize()} token has expired.")

            # Return payload
            return token_payload

        except jwt.ExpiredSignatureError as e:
            self.audit_logger.log_security_event(
                event_type=AuditEventType.TOKEN_VALIDATION_FAILURE,
                description=f"{token_type.capitalize()} token validation failed: {e!s}",
                severity=AuditSeverity.MEDIUM,
                metadata={"token_type": token_type, "error": str(e)},
            )
            raise TokenExpiredException(f"{token_type.capitalize()} token has expired.") from e

        except jwt.InvalidTokenError as e:
            self.audit_logger.log_security_event(
                event_type=AuditEventType.TOKEN_VALIDATION_FAILURE,
                description=f"{token_type.capitalize()} token validation failed: {e!s}",
                severity=AuditSeverity.HIGH,
                metadata={"token_type": token_type, "error": str(e)},
            )
            raise InvalidTokenException(f"{token_type.capitalize()} token is invalid.") from e

    async def blacklist_token(self, token: str, user_id: str | None = None) -> None:
        """
        Blacklist a token to prevent its future use.

        Args:
            token: The token to blacklist
            user_id: The ID of the user associated with the token

        Raises:
            InvalidTokenException: If the token is invalid
        """
        try:
            # Decode token without verification for logging
            token_data = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})

            # Check if we need to extract user_id from token
            if user_id is None:
                user_id = token_data.get("sub", "unknown")

            # Get token ID and session ID for tracking
            token_id = token_data.get("jti", "unknown")
            session_id = token_data.get("session_id", "unknown")

            # Blacklist the token
            self.blacklist_repo.add_to_blacklist(token, token_id)

            # Log the blacklisting
            self.audit_logger.log_security_event(
                event_type=AuditEventType.TOKEN_BLACKLISTED,
                user_id=user_id,
                description="Token blacklisted successfully",
                severity=AuditSeverity.INFO,
                metadata={"jti": token_id, "session_id": session_id},
            )

        except Exception as e:
            # If we can't decode, still try to blacklist the raw token
            self.blacklist_repo.add_to_blacklist(token)

            # Log the issue
            self.audit_logger.log_security_event(
                event_type=AuditEventType.TOKEN_BLACKLIST_FAILURE,
                user_id=user_id if user_id else "unknown",
                description="Failed to blacklist token due to decoding or other error",
                severity=AuditSeverity.WARNING,
                metadata={"error": str(e)},
            )

    async def blacklist_session_tokens(self, session_id: str, user_id: str | None = None) -> None:
        """
        Blacklist all tokens associated with a session.

        Args:
            session_id: The session ID to blacklist
            user_id: The ID of the user associated with the session
        """
        # For future implementation
        # Get all tokens for the session from repository
        # tokens = self.token_repo.get_tokens_by_session(session_id)

        # Blacklist each token
        # for token in tokens:
        #     self.blacklist_token(token.token_value, user_id)

        # Log the session blacklisting
        self.audit_logger.log_security_event(
            event_type=AuditEventType.SESSION_TOKENS_BLACKLISTED,
            user_id=user_id if user_id else "unknown",
            description="All tokens for session blacklisted successfully",
            severity=AuditSeverity.INFO,
            metadata={"session_id": session_id},
        )

    @property
    def settings(self) -> Settings:
        """Get the application settings."""
        return Settings()
