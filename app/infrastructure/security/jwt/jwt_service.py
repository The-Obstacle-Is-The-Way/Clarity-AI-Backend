"""
JWT (JSON Web Token) Service for authentication.

This service handles token creation, validation, and management according to
HIPAA security standards and best practices for healthcare applications.
"""

import uuid
from datetime import datetime, timedelta, UTC
from enum import Enum
from typing import Any, Dict, Optional, Union
from uuid import UUID
import traceback
import secrets
import hashlib

# Replace direct jose import with our adapter
from app.infrastructure.security.jwt.jose_adapter import (
    encode as jwt_encode,
    decode as jwt_decode,
    JWTError,
    ExpiredSignatureError
)
from pydantic import BaseModel, ValidationError, ConfigDict

from app.core.interfaces.services.jwt_service import IJwtService
from app.domain.entities.user import User
from app.domain.exceptions import AuthenticationError

try:
    from app.core.interfaces.repositories.user_repository_interface import IUserRepository
except ImportError:
    IUserRepository = Any

# Import the token blacklist repository interface
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository

from app.core.config.settings import Settings

# Import necessary exceptions from domain layer
from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

class TokenType(str, Enum):
    """Token types used in the application."""
    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"   # For password reset
    ACTIVATE = "activate"  # For account activation
    API = "api"  # For long-lived API tokens with restricted permissions


# Type definition for token blacklist dictionary
# Maps JTI (JWT ID) to expiration datetime
TokenBlacklistDict = dict[str, Union[datetime, float, str]]

class TokenPayload(BaseModel):
    """
    Model representing data contained in a JWT token.
    Uses Pydantic for validation and proper typing.
    """
    # Required standard JWT claims
    sub: str  # Subject (user identifier)
    exp: int  # Expiration time
    iat: int  # Issued at time
    jti: str  # JWT ID (unique identifier for this token)
    
    # Custom claims
    user_id: Optional[str] = None  # User ID (if different from sub)
    type: TokenType  # Token type (access, refresh, etc.)
    
    # Optional standard JWT claims
    iss: Optional[str] = None  # Issuer
    aud: Optional[str] = None  # Audience
    nbf: Optional[int] = None  # Not valid before

    # User-related claims
    email: Optional[str] = None  # User email
    name: Optional[str] = None  # User name
    role: Optional[str] = None  # Primary role
    roles: list[str] = []  # All roles
    permissions: list[str] = []  # Permissions
    
    # Token family for refresh tokens (prevents replay attacks)
    family_id: Optional[str] = None  # Family ID for refresh tokens
    parent_jti: Optional[str] = None  # Parent token ID for refresh tokens
    
    # Session identifier for logout/tracking
    session_id: Optional[str] = None  # Session ID
    
    # Model configuration
    model_config = ConfigDict(extra="ignore")  # Allow extra fields without validation errors

class JWTService(IJwtService):
    """
    Service for JWT token generation, validation and management.
    Implements secure token handling for HIPAA-compliant applications.
    Implements IJwtService.
    """
    
    def __init__(
        self,
        settings: Settings,
        user_repository: Optional[IUserRepository] = None,
        token_blacklist_repository: Optional[ITokenBlacklistRepository] = None
    ):
        """
        Initialize the JWT service with application settings.
        
        Args:
            settings: Application settings object.
            user_repository: Repository to fetch user details (optional, needed for get_user_from_token).
            token_blacklist_repository: Repository for token blacklisting (optional but recommended for security).
        """
        self.settings = settings
        # Use JWT_SECRET_KEY and handle potential SecretStr if using pydantic-settings correctly
        jwt_secret = getattr(settings, 'JWT_SECRET_KEY', None)
        if hasattr(jwt_secret, 'get_secret_value'):
             self.secret_key = jwt_secret.get_secret_value()
        elif jwt_secret:
             self.secret_key = str(jwt_secret)
        else:
             # Fallback or raise error if JWT_SECRET_KEY is missing and required
             self.secret_key = getattr(settings, 'SECRET_KEY', None) # Keep fallback for now
             if hasattr(self.secret_key, 'get_secret_value'): 
                 self.secret_key = self.secret_key.get_secret_value()
             if not self.secret_key:
                 logger.warning("JWT_SECRET_KEY not found in settings, falling back to SECRET_KEY or default.")
                 # Consider raising an error if JWT is essential and key is missing
                 self.secret_key = "default-secret-key-if-really-needed" # Example default

        self.algorithm = getattr(settings, 'JWT_ALGORITHM', 'HS256') # Use JWT_ALGORITHM
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        self.issuer = getattr(settings, 'JWT_ISSUER', None) # Use JWT_ISSUER
        self.audience = getattr(settings, 'JWT_AUDIENCE', None)

        self.user_repository = user_repository
        self.token_blacklist_repository = token_blacklist_repository

        # If no token blacklist repository is provided, use an in-memory fallback
        # This is NOT suitable for production, but prevents errors in development/testing
        # Token blacklist for revoked tokens
        # In production, this should be stored in Redis or similar through the repository
        self._token_blacklist: TokenBlacklistDict = {}
        
        if self.token_blacklist_repository is None:
            logger.warning("No token blacklist repository provided. Using in-memory blacklist, which is NOT suitable for production.")
        
        # Token family tracking for refresh token rotation
        # Maps family_id -> latest_jti to detect refresh token reuse
        self._token_families: dict[str, str] = {}
        # Maps jti -> family_id to quickly find a token's family
        self._token_family_map: dict[str, str] = {}
        
        logger.info(f"JWT service initialized with algorithm {self.algorithm}")

    async def _is_token_blacklisted(self, token: str) -> bool:
        """
        Check if a token (specifically its jti) is in the blacklist.
        
        Args:
            token: The JWT token to check
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        try:
            # Try with repository first if available
            if self.token_blacklist_repository is not None:
                try:
                    # Handle different interface methods that might be implemented
                    if hasattr(self.token_blacklist_repository, 'is_blacklisted'):
                        return await self.token_blacklist_repository.is_blacklisted(token)
                    elif hasattr(self.token_blacklist_repository, 'is_token_blacklisted'):
                        return await self.token_blacklist_repository.is_token_blacklisted(token)
                    else:
                        logger.warning("Token blacklist repository does not have expected methods")
                except Exception as repo_error:
                    logger.warning(f"Error using token blacklist repository: {repo_error}. Falling back to local blacklist.")
            
            # Make sure _token_blacklist exists
            if not hasattr(self, '_token_blacklist'):
                logger.debug("Initializing token blacklist dictionary")
                self._token_blacklist = {}
            
            try:
                # Fall back to local blacklist if repository unavailable or failed
                # Decode token without verification to extract the JTI
                unverified_payload = jwt_decode(
                    token, 
                    options={"verify_signature": False, "verify_aud": False, "verify_iss": False, "verify_exp": False}
                )
                jti = unverified_payload.get("jti")
                
                if jti and jti in self._token_blacklist:
                    # Check if blacklist entry itself is expired
                    expiry_time = self._token_blacklist[jti]
                    
                    # Handle different expiry time formats
                    if isinstance(expiry_time, (int, float)):
                        expiry_time = datetime.fromtimestamp(expiry_time, UTC)
                    elif isinstance(expiry_time, str):
                        try:
                            expiry_time = datetime.fromisoformat(expiry_time.replace('Z', '+00:00'))
                        except ValueError:
                            # Default to future date if we can't parse
                            expiry_time = datetime.now(UTC) + timedelta(days=1)
                    
                    if expiry_time > datetime.now(UTC):
                        return True
                    else:
                        # Clean up expired blacklist entry
                        del self._token_blacklist[jti]
                        logger.debug(f"Removed expired blacklist entry for JTI: {jti}")
            except JWTError:
                # If token can't be decoded, it's likely invalid anyway
                logger.debug("Could not decode token to check blacklist - malformed token")
                return False
            
            # Periodically clean the blacklist to prevent memory leaks
            self._clean_token_blacklist()
            return False
        except Exception as e:
            logger.warning(f"Error checking token blacklist: {e}")
            return False

    async def is_token_blacklisted(self, token: str) -> bool:
        """
        Check if a token has been blacklisted.
        
        Args:
            token: The JWT token to check
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        # Directly use internal implementation which handles repository fallback correctly
        return await self._is_token_blacklisted(token)

    async def is_jti_blacklisted(self, jti: str) -> bool:
        """
        Check if a token JTI has been blacklisted.
        
        Args:
            jti: The JWT ID to check
            
        Returns:
            True if the JTI is blacklisted, False otherwise
        """
        # Use the repository if available
        if self.token_blacklist_repository:
            if hasattr(self.token_blacklist_repository, 'is_jti_blacklisted'):
                return await self.token_blacklist_repository.is_jti_blacklisted(jti)
            
        # Fallback to in-memory implementation
        if not hasattr(self, '_token_blacklist'):
            self._token_blacklist = {}
            
        if jti in self._token_blacklist:
            # Handle different expiry time formats
            expiry_time = self._token_blacklist[jti]
            if isinstance(expiry_time, (int, float)):
                expiry_time = datetime.fromtimestamp(expiry_time, UTC)
            elif isinstance(expiry_time, str):
                try:
                    expiry_time = datetime.fromisoformat(expiry_time.replace('Z', '+00:00'))
                except ValueError:
                    # Default to future date if we can't parse
                    expiry_time = datetime.now(UTC) + timedelta(days=1)
                    
            # Check if it's expired
            if expiry_time > datetime.now(UTC):
                return True
            else:
                # Clean up expired entry
                del self._token_blacklist[jti]
                logger.debug(f"Removing expired JTI from blacklist: {jti}")
                
        return False
        
    async def blacklist_token(self, token: str, jti: str | None = None, expires_at: datetime | None = None, reason: str | None = None) -> bool:
        """
        Add a token to the blacklist.
        
        Args:
            token: The JWT token to blacklist
            jti: The JWT ID
            expires_at: When the token expires
            reason: Optional reason for blacklisting
            
        Returns:
            bool: True if the token was successfully blacklisted, False otherwise
        """
        try:
            # Use repository if available
            if self.token_blacklist_repository is not None:
                try:
                    result = await self.token_blacklist_repository.blacklist_token(
                        token, jti=jti, expires_at=expires_at, reason=reason
                    )
                    if result:
                        return True
                except Exception as repo_error:
                    logger.warning(f"Error using repository to blacklist token: {repo_error}. Falling back to local blacklist.")

            # Fall back to local blacklist
            if not jti or not expires_at:
                try:
                    # Decode the token to get jti and expiration without verification
                    unverified_payload = jwt_decode(
                        token, 
                        options={"verify_signature": False, "verify_aud": False, "verify_iss": False, "verify_exp": False}
                    )
                    jti = unverified_payload.get("jti", str(uuid.uuid4()))
                    exp_timestamp = unverified_payload.get("exp")
                    if exp_timestamp:
                        expires_at = datetime.fromtimestamp(exp_timestamp, UTC)
                    else:
                        # Default to 1 day if no expiration found
                        expires_at = datetime.now(UTC) + timedelta(days=1)
                except Exception as e:
                    logger.warning(f"Error decoding token for blacklisting: {e}")
                    # Generate default values if token can't be decoded
                    jti = jti or str(uuid.uuid4())
                    expires_at = expires_at or (datetime.now(UTC) + timedelta(days=1))

            # Ensure _token_blacklist exists
            if not hasattr(self, '_token_blacklist'):
                self._token_blacklist = {}
                
            # Add to local blacklist
            self._token_blacklist[jti] = expires_at
            logger.info(f"Token with JTI {jti} blacklisted until {expires_at}")
            return True
        except Exception as e:
            logger.error(f"Error blacklisting token: {e}")
            return False

    def _clean_token_blacklist(self) -> None:
        """Removes expired entries from the token blacklist."""
        if not hasattr(self, '_token_blacklist') or not self._token_blacklist:
            return
            
        now = datetime.now(UTC)
        expired_jtis = []
        
        for jti, expiry in self._token_blacklist.items():
            # Handle different expiry time formats
            if isinstance(expiry, (int, float)):
                expiry_time = datetime.fromtimestamp(expiry, UTC)
            elif isinstance(expiry, str):
                try:
                    expiry_time = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
                except ValueError:
                    # Skip if we can't parse the time
                    continue
            else:
                expiry_time = expiry
                
            if expiry_time <= now:
                expired_jtis.append(jti)
        
        for jti in expired_jtis:
            try:
                del self._token_blacklist[jti]
                logger.debug(f"Removed expired JTI {jti} from blacklist.")
            except KeyError:
                pass  # Already removed

    async def blacklist_session(self, session_id: str) -> bool:
        """
        Blacklists all tokens associated with a specific session.
        
        Args:
            session_id: The session ID to blacklist
            
        Returns:
            bool: True if the session was successfully blacklisted, False otherwise
        """
        try:
            # Use repository if available
            if self.token_blacklist_repository is not None:
                if hasattr(self.token_blacklist_repository, 'blacklist_session'):
                    return await self.token_blacklist_repository.blacklist_session(session_id)
                else:
                    logger.warning("Token blacklist repository does not support session blacklisting")
            
            # Fallback to simple in-memory implementation - track sessions in a separate dict
            if not hasattr(self, '_session_blacklist'):
                self._session_blacklist = {}
                
            # Blacklist session for 30 days (a reasonable default for session expiry)
            expiry = datetime.now(UTC) + timedelta(days=30)
            self._session_blacklist[session_id] = expiry
            logger.info(f"Session {session_id} blacklisted until {expiry}")
            return True
            
        except Exception as e:
            logger.error(f"Error blacklisting session: {e}")
            return False
            
    async def is_session_blacklisted(self, session_id: str) -> bool:
        """
        Check if a session is blacklisted.
        
        Args:
            session_id: The session ID to check
            
        Returns:
            bool: True if the session is blacklisted, False otherwise
        """
        try:
            # Use repository if available
            if self.token_blacklist_repository is not None:
                if hasattr(self.token_blacklist_repository, 'is_session_blacklisted'):
                    return await self.token_blacklist_repository.is_session_blacklisted(session_id)
            
            # Fallback to in-memory implementation
            if not hasattr(self, '_session_blacklist'):
                return False
                
            if session_id in self._session_blacklist:
                expiry_time = self._session_blacklist[session_id]
                if isinstance(expiry_time, (int, float)):
                    expiry_time = datetime.fromtimestamp(expiry_time, UTC)
                elif isinstance(expiry_time, str):
                    try:
                        expiry_time = datetime.fromisoformat(expiry_time.replace('Z', '+00:00'))
                    except ValueError:
                        # Default to future date if we can't parse
                        expiry_time = datetime.now(UTC) + timedelta(days=1)
                
                if expiry_time > datetime.now(UTC):
                    return True
                else:
                    # Clean up expired entry
                    del self._session_blacklist[session_id]
                    logger.debug(f"Removing expired session from blacklist: {session_id}")
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking session blacklist: {e}")
            return False


    def revoke_token(self, token: str) -> bool:
        """Revoke a token by adding it to the blacklist.
        
        Args:
            token: The token to revoke
            
        Returns:
            bool: True if the token was successfully revoked
        """
        return self.blacklist_token(token)

def get_jwt_service() -> IJwtService:
    """
    Factory function to create a JWTService instance.
    
    This function allows for dependency injection in FastAPI.
    
    Returns:
        An instance of IJwtService
    """
    settings = get_settings()
    user_repo = get_user_repository()
    blacklist_repo = get_token_blacklist_repository()
    
    try:
        return JWTService(settings, user_repo, blacklist_repo)
    except Exception as e:
        logger.error(f"Error initializing JWTService: {e}")
        raise e from None
