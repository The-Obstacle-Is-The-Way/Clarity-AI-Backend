# -*- coding: utf-8 -*-
"""
JWT (JSON Web Token) Service for authentication.

This service handles token creation, validation, and management according to
HIPAA security standards and best practices for healthcare applications.
"""

import time
import uuid
import secrets
from typing import Dict, Optional, Any, List, Tuple, Union
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi import Depends, HTTPException, status
from pydantic import BaseModel
from uuid import UUID

from app.core.interfaces.services.jwt_service import IJwtService
from app.domain.exceptions import AuthenticationError
from app.domain.entities.user import User
try:
    from app.core.interfaces.repositories.user_repository import IUserRepository
except ImportError:
    IUserRepository = Any
from app.config.settings import Settings, get_settings
from app.infrastructure.logging.logger import get_logger

# Import necessary exceptions from domain layer
from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException

logger = get_logger(__name__)

class TokenType:
    """Token types used in the application."""
    ACCESS = "access"
    REFRESH = "refresh"

class TokenPayload(BaseModel):
    """Pydantic model for JWT payload validation."""
    sub: str | UUID # Subject (user ID)
    exp: int        # Expiration time (Unix timestamp)
    iat: int        # Issued at time (Unix timestamp)
    jti: str | UUID # JWT ID
    iss: str | None = None # Issuer
    aud: str | List[str] | None = None # Audience
    type: str       # Token type (e.g., 'access', 'refresh')
    roles: List[str] | None = [] # User roles
    # Add other custom claims as needed
    # permissions: List[str] | None = []

    class Config:
        extra = 'allow' # Allow extra fields not explicitly defined

class JWTService(IJwtService):
    """
    Service for JWT token generation, validation and management.
    Implements secure token handling for HIPAA-compliant applications.
    Implements IJwtService.
    """
    
    def __init__(self, settings: Settings, user_repository: Optional[IUserRepository] = None):
        """
        Initialize the JWT service with application settings.
        
        Args:
            settings: Application settings object.
            user_repository: Repository to fetch user details (optional, needed for get_user_from_token).
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
        self.audience = getattr(settings, 'JWT_AUDIENCE', None) # Use JWT_AUDIENCE

        self.user_repository = user_repository

        # Token blacklist for revoked tokens
        # In production, this should be stored in Redis or similar
        self._token_blacklist: Dict[str, datetime] = {}
        
        logger.info(f"JWT service initialized with algorithm {self.algorithm}")

    async def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta_minutes: Optional[int] = None
    ) -> str:
        """Creates a new access token based on the provided data dictionary."""
        subject = data.get("sub") or data.get("user_id")
        if not subject:
            raise ValueError("Subject ('sub' or 'user_id') is required in data to create access token")

        subject_str = str(subject)

        # Calculate expiration time
        expire_minutes = expires_delta_minutes or self.access_token_expire_minutes
        expires_delta = timedelta(minutes=expire_minutes)

        now = datetime.now(timezone.utc)
        expire_time = now + expires_delta

        # Generate a unique token ID (jti) if not provided
        token_id = data.get("jti", str(uuid.uuid4()))

        # Prepare payload
        to_encode = {
            "sub": subject_str,
            "exp": int(expire_time.timestamp()),
            "iat": int(now.timestamp()),
            "jti": token_id,
            "iss": self.issuer,
            "aud": self.audience,
            "type": TokenType.ACCESS,
            "scope": TokenType.ACCESS,
            # Add other claims from input data, excluding reserved claims
            **{k: v for k, v in data.items() if k not in ["sub", "exp", "iat", "jti", "iss", "aud", "type", "scope"]}
        }

        # Ensure role/roles consistency if present
        if "role" in to_encode and "roles" not in to_encode:
            to_encode["roles"] = [to_encode["role"]]
        elif "roles" in to_encode and "role" not in to_encode and to_encode["roles"]:
            to_encode["role"] = to_encode["roles"][0] # Set first role as primary

        try:
            # Ensure all payload values are serializable (e.g., convert UUIDs)
            serializable_payload = self._make_payload_serializable(to_encode)
            encoded_token = jwt.encode(
                serializable_payload, self.secret_key, algorithm=self.algorithm
            )
        except TypeError as e:
            logger.error(f"JWT Encoding Error: {e}. Payload: {serializable_payload}")
            raise AuthenticationError("Failed to encode token due to unserializable data.") from e

        logger.debug(f"Created access token with ID {token_id} for subject {subject_str}")
        return encoded_token

    async def create_refresh_token(
        self,
        data: Dict[str, Any],
        expires_delta_minutes: Optional[int] = None
    ) -> str:
        """Creates a new refresh token."""
        subject = data.get("sub") or data.get("user_id")
        if not subject:
            raise ValueError("Subject ('sub' or 'user_id') is required in data to create refresh token")

        subject_str = str(subject)

        # Use configured refresh token expiry (days), converted to minutes if needed
        if expires_delta_minutes is None:
            expire_days = self.refresh_token_expire_days
            expires_delta = timedelta(days=expire_days)
        else:
            # Allow override via minutes if provided
            expires_delta = timedelta(minutes=expires_delta_minutes)

        now = datetime.now(timezone.utc)
        expire_time = now + expires_delta

        # Generate a unique token ID (jti) if not provided
        token_id = data.get("jti", str(uuid.uuid4()))

        to_encode = {
            "sub": subject_str,
            "exp": int(expire_time.timestamp()),
            "iat": int(now.timestamp()),
            "jti": token_id,
            "iss": self.issuer,
            "aud": self.audience,
            "type": TokenType.REFRESH,
            # Add other claims from input data, excluding reserved claims
            **{k: v for k, v in data.items() if k not in ["sub", "exp", "iat", "jti", "iss", "aud", "type"]}
        }

        try:
            serializable_payload = self._make_payload_serializable(to_encode)
            encoded_token = jwt.encode(
                serializable_payload, self.secret_key, algorithm=self.algorithm
            )
        except TypeError as e:
            logger.error(f"JWT Refresh Encoding Error: {e}. Payload: {serializable_payload}")
            raise AuthenticationError("Failed to encode refresh token due to unserializable data.") from e

        logger.debug(f"Created refresh token with ID {token_id} for subject {subject_str}")
        return encoded_token

    async def decode_token(self, token: str) -> TokenPayload:
        """
        Decodes a token, verifies signature, expiration, and checks blacklist.
        Raises AuthenticationError or specific token exceptions for validation failures.
        Returns a validated TokenPayload object.
        """
        if not token:
            raise InvalidTokenException("Token is missing.")

        # Check blacklist first
        logger.debug("Checking token against blacklist...")
        if self._is_token_blacklisted(token):
            logger.warning(f"Attempted use of blacklisted token.")
            raise AuthenticationError("Token has been revoked.") # Or a specific RevokedTokenException

        try:
            logger.debug(f"Attempting to decode token with: Algorithm={self.algorithm}, Audience={self.audience}, Issuer={self.issuer}")
            payload_dict = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer
            )
            logger.debug(f"Raw decoded payload: {payload_dict}")
            
            # Validate payload structure using Pydantic model
            logger.debug("Validating payload structure with TokenPayload model...")
            try:
                validated_payload = TokenPayload.model_validate(payload_dict)
                logger.debug(f"Payload structure validated successfully: {validated_payload}")
            except Exception as validation_error: # Catch Pydantic validation errors
                logger.warning(f"Token payload validation failed: {validation_error}")
                raise InvalidTokenException(f"Invalid token structure: {validation_error}")

            return validated_payload

        except ExpiredSignatureError:
            logger.info("Token has expired.")
            raise TokenExpiredException("Token has expired.")
        except JWTError as e:
            logger.warning(f"JWT decoding error: {e}")
            # Distinguish between different JWT errors if needed
            raise InvalidTokenException(f"Invalid token: {e}")
        except Exception as e:
            # Catch unexpected errors during decoding or validation
            logger.error(f"Unexpected error during token decoding: {e}", exc_info=True)
            raise AuthenticationError("An unexpected error occurred while validating the token.")

    async def verify_refresh_token(self, refresh_token: str) -> TokenPayload:
        """Verifies a refresh token and returns its payload."""
        payload = await self.decode_token(refresh_token)

        # Additional checks specific to refresh tokens
        if payload.type != TokenType.REFRESH:
            raise InvalidTokenException("Invalid token type: Expected refresh token.")

        # Potentially check against a database of valid refresh tokens/sessions here

        return payload

    async def get_user_from_token(self, token: str) -> Optional[User]:
        """Decode the token and fetch the user from the repository."""
        logger.debug("Attempting to get user from token...")
        if not self.user_repository:
            logger.warning("User repository not set in JWTService, cannot fetch user.")
            return None
        
        try:
            logger.debug(f"Decoding token to extract user payload...")
            payload: TokenPayload = await self.decode_token(token) # Re-uses the validation logic
            logger.debug(f"Token decoded successfully. Payload: {payload}")

            # Extract user identifier (assuming it's stored in 'sub' claim)
            user_id_str = payload.sub
            logger.debug(f"Extracted user ID string from token payload: {user_id_str}")
            if not user_id_str:
                logger.warning("No 'sub' (user ID) found in token payload.")
                return None
            
            try:
                logger.debug(f"Attempting to parse user ID string '{user_id_str}' to UUID.")
                user_id = UUID(user_id_str)
                logger.debug(f"User ID parsed successfully: {user_id}")
            except ValueError as e:
                logger.error(f"Invalid user ID format in token 'sub' claim: {user_id_str}. Error: {e}")
                return None

            logger.debug(f"Fetching user with ID {user_id} from repository {type(self.user_repository).__name__}...")
            user = await self.user_repository.get_by_id(user_id)
            if user:
                logger.debug(f"User found in repository: {user.email} (ID: {user.id})")
                return user
            else:
                logger.warning(f"User with ID {user_id} not found in the repository.")
                return None
            
        except AuthenticationError as e: # Catches errors from decode_token
            logger.warning(f"Authentication error while getting user from token: {e}")
            # Depending on policy, you might re-raise or return None
            return None # Or raise AuthenticationError("Failed to authenticate token.")
        except Exception as e:
            logger.exception(f"Unexpected error retrieving user from token: {e}")
            raise AuthenticationError("Failed to retrieve user information from token.")

    def get_token_payload_subject(self, payload: TokenPayload) -> Optional[str]:
        """Extracts the subject ('sub') claim from the token payload.
        Returns None if the subject is missing or invalid.
        """
        if not isinstance(payload, TokenPayload):
             # Handle cases where payload might not be a TokenPayload object yet
             # This might occur if called before full validation in decode_token
             sub = payload.get("sub")
        else:
             sub = payload.sub # Access via attribute

        if not sub:
            logger.warning("Subject ('sub') claim missing from token payload.")
            return None
        return str(sub)

    def _is_token_blacklisted(self, token: str) -> bool:
        """Check if a token (specifically its jti) is in the blacklist."""
        try:
            # Quick unverified decode just for JTI (less secure if key is compromised)
            unverified_payload = jwt.decode(
                token, 
                self.secret_key, # Provide the key even for unverified decode
                options={"verify_signature": False, "verify_aud": False, "verify_iss": False, "verify_exp": False}
            )
            jti = unverified_payload.get("jti")
            if jti and jti in self._token_blacklist:
                # Check if blacklist entry itself is expired (token expired anyway)
                if self._token_blacklist[jti] > datetime.now(timezone.utc):
                    return True
                else:
                    # Clean up expired blacklist entry
                    del self._token_blacklist[jti]
        except JWTError:
            # If it doesn't even decode unverified, it's invalid anyway
            return False
        return False

    async def revoke_token(self, token: str) -> None:
        """Revokes a token by adding its JTI to the blacklist."""
        try:
            # Decode requires verification here to ensure we only blacklist valid tokens
            payload = await self.decode_token(token)
            jti = payload.get("jti")
            exp = payload.get("exp")

            if jti and exp:
                # Store JTI with its original expiry time
                expiry_datetime = datetime.fromtimestamp(exp, tz=timezone.utc)
                self._token_blacklist[jti] = expiry_datetime
                logger.info(f"Token with JTI {jti} blacklisted until {expiry_datetime}.")
                # Periodically clean the blacklist
                self._clean_token_blacklist()
            else:
                logger.warning("Attempted to revoke token without JTI or EXP claim.")

        except AuthenticationError as e:
            logger.warning(f"Attempted to revoke an invalid/expired token: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during token revocation: {e}")

    def _clean_token_blacklist(self) -> None:
        """Removes expired entries from the token blacklist."""
        now = datetime.now(timezone.utc)
        expired_jtis = [
            jti for jti, expiry in self._token_blacklist.items() if expiry <= now
        ]
        for jti in expired_jtis:
            try:
                del self._token_blacklist[jti]
                logger.debug(f"Removed expired JTI {jti} from blacklist.")
            except KeyError:
                pass # Already removed

    def _make_payload_serializable(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure all values in payload are JSON serializable (e.g., converts UUID)."""
        serializable = {}
        for key, value in payload.items():
            if isinstance(value, UUID):
                serializable[key] = str(value)
            elif isinstance(value, datetime):
                # Ensure datetime is represented as timestamp int for JWT standard claims
                if key in ['exp', 'iat', 'nbf']:
                    serializable[key] = int(value.timestamp())
                else: # Otherwise use ISO format for custom claims
                    serializable[key] = value.isoformat()
            elif isinstance(value, list):
                serializable[key] = [str(item) if isinstance(item, UUID) else item for item in value]
            elif isinstance(value, timedelta): # Should not happen if calculated correctly
                serializable[key] = value.total_seconds() # Or handle differently
            else:
                serializable[key] = value
        return serializable
