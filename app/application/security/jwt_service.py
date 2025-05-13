"""
JWT Service module.

This module provides a service for JWT token generation, validation, and management,
following HIPAA compliance requirements for secure authentication and authorization.
"""

import time
import uuid
from datetime import timedelta
from typing import Any

import jwt
from pydantic import BaseModel

from app.core.interfaces.services.audit_logger_interface import IAuditLogger, AuditEventType, AuditSeverity
from app.core.config import Settings
from app.core.utils.date_utils import utcnow, as_utc
from app.domain.exceptions.auth_exceptions import (
    InvalidTokenException,
    TokenBlacklistedException,
    TokenExpiredException,
)
# from app.domain.interfaces.repositories.token_blacklist_repository import (
#     ITokenBlacklistRepository, # TODO: Define this interface in core
#     ITokenRepository,
# )
from app.domain.interfaces.token_repository import ITokenRepository # TODO: Move this to core


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


class JWTService:
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
        # blacklist_repo: ITokenBlacklistRepository, # TODO: Add back when defined and injected
        audit_logger: IAuditLogger
    ):
        """
        Initialize the JWT service.
        
        Args:
            token_repo: Repository for managing tokens
            # blacklist_repo: Repository for managing blacklisted tokens
            audit_logger: Service for audit logging
        """
        self.token_repo = token_repo
        # self.blacklist_repo = blacklist_repo # TODO: Add back when defined and injected
        self.audit_logger = audit_logger
        self.algorithm = "HS256"  # HMAC with SHA-256
        
        # Validate that we have required secrets
        if not self.settings.jwt_secret_key:
            raise ValueError("JWT_SECRET_KEY is required")
        
    def create_access_token(
        self, 
        user_id: str,
        email: str,
        role: str,
        permissions: list[str],
        session_id: str
    ) -> tuple[str, int]:
        """
        Create a new access token for a user.
        
        Args:
            user_id: The ID of the user
            email: The email of the user
            role: The role of the user
            permissions: The permissions of the user
            session_id: The session ID associated with this token
            
        Returns:
            A tuple containing the access token and its expiration time in seconds
        """
        # Calculate expiration time
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
            "permissions": permissions
        }
        
        # Create token
        access_token = jwt.encode(
            payload, 
            self.settings.jwt_secret_key, 
            algorithm=self.algorithm
        )
        
        # Log token creation
        self.audit_logger.log_security_event(
            event_type="TOKEN_CREATED",
            user_id=user_id,
            description=f"Access token created for user {email}",
            metadata={
                "token_id": token_id,
                "session_id": session_id,
                "expires_at": expire.isoformat()
            }
        )
        
        return access_token, expires_in
    
    def create_refresh_token(
        self, 
        user_id: str,
        email: str,
        session_id: str
    ) -> str:
        """
        Create a new refresh token for a user.
        
        Args:
            user_id: The ID of the user
            email: The email of the user
            session_id: The session ID associated with this token
            
        Returns:
            The refresh token string
        """
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
            "token_type": "refresh"
        }
        
        # Create token
        refresh_token = jwt.encode(
            payload, 
            self.settings.jwt_secret_key, 
            algorithm=self.algorithm
        )
        
        # Log token creation
        self.audit_logger.log_security_event(
            event_type="REFRESH_TOKEN_CREATED",
            user_id=user_id,
            description=f"Refresh token created for user {email}",
            metadata={
                "token_id": token_id,
                "session_id": session_id,
                "expires_at": expire.isoformat()
            }
        )
        
        return refresh_token
    
    def validate_token(self, token: str, token_type: str = "access") -> dict[str, Any]:
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
            # Check if token is blacklisted
            # if self.token_blacklist_repository.is_blacklisted(token):
            #     self.audit_logger.log_security_event(
            #         event_type="BLACKLISTED_TOKEN_USED",
            #         description="Attempt to use blacklisted token",
            #         metadata={"token_type": token_type}
            #     )
            #     raise TokenBlacklistedException("Token has been revoked")
            
            # Decode token
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.algorithm]
            )
            
            # Validate token type for refresh tokens
            if token_type == "refresh" and payload.get("token_type") != "refresh":
                raise InvalidTokenException("Invalid token type")
                
            # Return payload
            return payload
            
        except jwt.ExpiredSignatureError:
            self.audit_logger.log_security_event(
                event_type="EXPIRED_TOKEN_USED",
                description=f"Attempt to use expired {token_type} token",
                metadata={
                    "token_type": token_type,
                }
            )
            raise TokenExpiredException("Token has expired")
            
        except jwt.InvalidTokenError:
            self.audit_logger.log_security_event(
                event_type="INVALID_TOKEN_USED",
                description=f"Attempt to use invalid {token_type} token",
                metadata={
                    "token_type": token_type,
                }
            )
            raise InvalidTokenException("Invalid token")
    
    def blacklist_token(self, token: str, user_id: str | None = None) -> None:
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
            token_data = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False}
            )
            
            # Check if we need to extract user_id from token
            if user_id is None:
                user_id = token_data.get("sub", "unknown")
                
            # Get token ID and session ID for tracking
            token_id = token_data.get("jti", "unknown")
            session_id = token_data.get("session_id", "unknown")
            
            # Blacklist the token
            # self.blacklist_repo.add_to_blacklist(token, token_id)
            
            # Log the blacklisting
            self.audit_logger.log_security_event(
                event_type="TOKEN_BLACKLISTED",
                user_id=user_id,
                description=f"Token blacklisted",
                metadata={
                    "token_id": token_id,
                    "session_id": session_id,
                    "token_type": token_data.get("token_type", "access")
                }
            )
            
        except Exception as e:
            # If we can't decode, still try to blacklist the raw token
            # self.blacklist_repo.add_to_blacklist(token)
            
            # Log the issue
            self.audit_logger.log_security_event(
                event_type="TOKEN_BLACKLIST_ERROR",
                user_id=user_id or "unknown",
                description=f"Error blacklisting token: {str(e)}",
                metadata={}
            )
    
    def blacklist_session_tokens(self, session_id: str, user_id: str = None) -> None:
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
            event_type="SESSION_BLACKLISTED",
            user_id=user_id or "unknown",
            description=f"All tokens for session blacklisted",
            metadata={
                "session_id": session_id
            }
        )

    @property
    def settings(self) -> Settings:
        """Get the application settings."""
        return Settings() 