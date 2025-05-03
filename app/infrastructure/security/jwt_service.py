"""
JWT service provider.

This module provides a single source of truth for JWT token services following
clean architecture principles. It implements dependency injection patterns
that ensure testability and meet HIPAA compliance requirements.
"""

from functools import lru_cache
from typing import Dict, Any, Optional, List, Union

from fastapi import Depends
from jose import jwt, JWTError, ExpiredSignatureError

from app.core.config.settings import Settings, get_settings
from app.core.interfaces.services.jwt_service import IJwtService
from app.domain.entities.user import User
from app.domain.exceptions import AuthenticationError
from app.infrastructure.logging.logger import get_logger

import asyncio
import time
import uuid
import secrets
from datetime import datetime, timedelta, timezone

logger = get_logger(__name__)


class JWTService(IJwtService):
    """
    Implementation of the JWT service interface.
    
    This service handles token creation, validation, and management
    according to HIPAA security standards and best practices for 
    healthcare applications.
    """
    
    def __init__(self, settings: Settings):
        """
        Initialize the JWT service with application settings.
        
        Args:
            settings: Application settings object.
        """
        self.settings = settings
        # Use JWT_SECRET_KEY and handle potential SecretStr
        jwt_secret = getattr(settings, 'JWT_SECRET_KEY', None)
        if hasattr(jwt_secret, 'get_secret_value'):
            self.secret_key = jwt_secret.get_secret_value()
        elif jwt_secret:
            self.secret_key = str(jwt_secret)
        else:
            # Fallback to SECRET_KEY
            self.secret_key = getattr(settings, 'SECRET_KEY', None)
            if hasattr(self.secret_key, 'get_secret_value'): 
                self.secret_key = self.secret_key.get_secret_value()
            if not self.secret_key:
                logger.warning("JWT_SECRET_KEY not found, falling back to default (INSECURE FOR PRODUCTION)")
                self.secret_key = "insecure-default-key-change-in-production"
        
        self.algorithm = getattr(settings, 'JWT_ALGORITHM', 'HS256')
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = getattr(settings, 'JWT_REFRESH_TOKEN_EXPIRE_DAYS', 7)
        self.issuer = getattr(settings, 'JWT_ISSUER', None)
        self.audience = getattr(settings, 'JWT_AUDIENCE', None)
        
        # Token blacklist for revoked tokens
        # In production, this should be stored in Redis or similar
        self._token_blacklist: Dict[str, Any] = {}
        
        logger.info(f"JWT service initialized with algorithm {self.algorithm}")
    
    async def create_access_token(self, data: Dict[str, Any], expires_delta_minutes: Optional[int] = None) -> str:
        """
        Create a new access token.
        
        Args:
            data: Dictionary containing claims to include in the token
            expires_delta_minutes: Optional override for token expiration in minutes
            
        Returns:
            JWT access token as a string
        """
        return self._create_token(
            data=data, 
            token_type="access",
            expires_delta_minutes=expires_delta_minutes or self.access_token_expire_minutes
        )
    
    async def create_refresh_token(self, data: Dict[str, Any], expires_delta_minutes: Optional[int] = None) -> str:
        """
        Create a new refresh token.
        
        Args:
            data: Dictionary containing claims to include in the token
            expires_delta_minutes: Optional override for token expiration in minutes
            
        Returns:
            JWT refresh token as a string
        """
        # Handle both minutes or days format for backward compatibility
        if expires_delta_minutes and expires_delta_minutes < 1000:  # Likely days not minutes
            minutes = expires_delta_minutes * 24 * 60
        else:
            minutes = expires_delta_minutes or (self.refresh_token_expire_days * 24 * 60)
            
        return self._create_token(
            data=data,
            token_type="refresh",
            expires_delta_minutes=minutes
        )
    
    def _create_token(self, data: Dict[str, Any], token_type: str, expires_delta_minutes: int) -> str:
        """
        Internal method to create a JWT token with common logic.
        
        Args:
            data: Dictionary containing claims to include in the token
            token_type: Type of token (access/refresh)
            expires_delta_minutes: Token expiration in minutes
            
        Returns:
            JWT token as a string
        """
        payload = data.copy()
        expires = self._get_expiration_timestamp(expires_delta_minutes)
        
        # Add standard claims
        payload.update({
            "exp": expires,
            "iat": self._get_current_timestamp(),
            "jti": self._generate_jwt_id(),
            "type": token_type
        })
        
        # Add optional claims if configured
        if self.issuer:
            payload["iss"] = self.issuer
        if self.audience:
            payload["aud"] = self.audience
            
        # Make serializable (handle UUIDs, etc.)
        payload = self._make_payload_serializable(payload)
        
        # Create the token
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    async def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and verify a JWT token.
        
        Args:
            token: JWT token string to verify
            
        Returns:
            Dictionary containing the token claims
            
        Raises:
            AuthenticationError: If token is invalid, expired, etc.
        """
        try:
            # Decode and verify the token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": True}
            )
            
            # Check if token is blacklisted
            if self._is_token_blacklisted(payload.get("jti", "")):
                raise AuthenticationError("Token has been revoked")
                
            return payload
            
        except ExpiredSignatureError:
            raise AuthenticationError("Token has expired") from None
        except JWTError:
            raise AuthenticationError("Invalid token") from None
            
    # Alias for backward compatibility
    async def verify_token(self, token: str) -> Dict[str, Any]:
        """Alias for decode_token to maintain backward compatibility."""
        return await self.decode_token(token)
    
    async def verify_refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Verify a refresh token and return its payload.

        A thin wrapper around ``decode_token`` that additionally checks the
        ``type`` claim equals ``"refresh"``.  Any decoding/expiry errors are
        surfaced unchanged as ``AuthenticationError`` so upstream callers can
        react consistently.
        """
        payload = await self.decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise AuthenticationError("Invalid token type – expected refresh token")
        return payload
    
    async def refresh_access_token(self, refresh_token: str) -> str:
        """Generate a new access token based on a valid refresh token.
        
        Args:
            refresh_token: A valid JWT refresh token
            
        Returns:
            A new JWT access token
            
        Raises:
            AuthenticationError: If the refresh token is invalid or expired
        """
        # Verify the refresh token is valid
        payload = await self.verify_refresh_token(refresh_token)
        
        # Extract the core identity claims for the new token
        data = {}
        for claim in ["sub", "role", "roles", "email", "username"]:
            if claim in payload:
                data[claim] = payload[claim]
                
        # Create a new access token with the extracted identity
        return await self.create_access_token(data)
        
    async def get_token_identity(self, token: str) -> str:
        """Extract the subject (identity) from a token.
        
        Args:
            token: JWT token
            
        Returns:
            The subject claim (usually the user ID)
            
        Raises:
            AuthenticationError: If token is invalid or does not contain a subject
        """
        payload = await self.decode_token(token)
        subject = payload.get("sub")
        
        if not subject:
            raise AuthenticationError("Token does not contain identity information")
            
        return subject

    async def get_user_from_token(self, token: str) -> User:  # type: ignore[override]
        """Construct a User entity from token claims.
        
        Extracts user claims from the token and constructs a User entity.
        
        Args:
            token: JWT token
            
        Returns:
            User entity populated with data from token claims
            
        Raises:
            AuthenticationError: If token is invalid or missing required claims

        Unlike the full-featured JWT service which performs a repository lookup,
        this method constructs a User entity directly from the token claims for
        use in unit tests and situations where database access is not needed.
        """
        # Decode the token and extract user claims
        payload = await self.decode_token(token)
        
        # Extract required user attributes from payload
        user_id_str = payload.get("sub")
        if not user_id_str:
            raise AuthenticationError("Token missing required 'sub' claim")
            
        try:
            # Convert string user_id to UUID if possible
            from uuid import UUID
            user_id = UUID(user_id_str)
        except ValueError:
            # If not a valid UUID, use the string as is
            user_id = user_id_str
            
        # Extract other user attributes with defaults
        email = payload.get("email", "")
        username = payload.get("username", "")
        role = payload.get("role", "")
        
        # Extract roles list if available or create from single role
        roles = payload.get("roles", [])
        if not roles and role:
            roles = [role]
            
        # Optional attributes
        is_active = payload.get("is_active", True)
        
        # Create and return the User entity
        return User(
            id=user_id,
            email=email,
            username=username,
            role=role,
            roles=roles,
            is_active=is_active
        )

    def get_token_payload_subject(self, payload: Dict[str, Any]):  # type: ignore[override]
        """Extract the ``sub`` claim if present."""
        return payload.get("sub")
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token by adding it to the blacklist.
        
        Args:
            token: JWT token to revoke
            
        Returns:
            True if token was successfully blacklisted
        """
        try:
            # Extract the JTI (JWT ID) from the token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": True}
            )
            jti = payload.get("jti")
            if jti:
                self._token_blacklist[jti] = self._get_current_timestamp()
                return True
        except (JWTError, ExpiredSignatureError):
            # Don't raise for already expired tokens
            pass
        return False
    
    def _is_token_blacklisted(self, jti: str) -> bool:
        """
        Check if a token is in the blacklist.
        
        Args:
            jti: JWT ID to check
            
        Returns:
            True if token is blacklisted
        """
        return jti in self._token_blacklist
    
    def _get_current_timestamp(self) -> int:
        """Get current Unix timestamp."""
        return int(time.time())
    
    def _get_expiration_timestamp(self, minutes: int) -> int:
        """Calculate expiration timestamp from current time."""
        return self._get_current_timestamp() + (minutes * 60)
    
    def _generate_jwt_id(self) -> str:
        """Generate a unique JWT ID."""
        return str(uuid.uuid4())
    
    def _make_payload_serializable(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure all values in payload are JSON serializable.
        
        Args:
            payload: Token payload dictionary
            
        Returns:
            Serializable payload dictionary
        """
        result = {}
        for key, value in payload.items():
            if hasattr(value, "__str__"):
                result[key] = str(value)
            else:
                result[key] = value
        return result


@lru_cache
async def get_jwt_service(
    settings: Settings = Depends(get_settings),
) -> IJwtService:
    """Return a *concrete* ``JWTService`` instance.

    When executed *outside* FastAPI’s dependency-injection (e.g. in unit-tests
    or middleware manual initialisation) the ``settings`` argument will receive
    the literal ``Depends`` *marker* instead of a resolved ``Settings`` object.
    We therefore detect that case and synchronously acquire a real instance of
    :class:`Settings` so the service constructor does not blow up.
    """
    # When called outside FastAPI's DI system the *settings* argument will be
    # the *Depends* marker instance instead of a concrete ``Settings`` object.
    # We therefore need to detect that case *robustly* (using ``isinstance``)
    # and synchronously obtain a real ``Settings`` instance.
    from fastapi.params import Depends as DependsClass  # local import to avoid hard dep at module import time

    if isinstance(settings, DependsClass):
        candidate = get_settings()
        # ``get_settings`` may or may not be awaitable depending on impl.
        if asyncio.iscoroutine(candidate):
            settings = await candidate  
        else:  # pragma: no cover – current impl is sync
            settings = candidate  

    # Defensive fallback – should never happen but keeps tests green.
    if not isinstance(settings, Settings):
        settings = get_settings()  
        if asyncio.iscoroutine(settings):  
            settings = await settings  

    return JWTService(settings)
