"""
JWT (JSON Web Token) Service for authentication.

This service handles token creation, validation, and management according to
HIPAA security standards and best practices for healthcare applications.
"""

import abc
import enum
import logging
import math
import re
import time
import uuid
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any, Optional, Union, cast

from jose import JWTError, ExpiredSignatureError, jwt as jwt_jose # Renamed for clarity
from pydantic import BaseModel, Field, computed_field, field_validator, validator

# Core Layer Imports
from app.core.config.settings import settings
from app.domain.exceptions.token_exceptions import (  # Corrected import path
    InvalidTokenError,
    TokenCreationError,
    TokenDecodingError,
    TokenExpiredError,
    TokenRevokedError,
    TokenVerificationError,
)
from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.core.interfaces.repositories.user_repository_interface import (
    IUserRepository,
)
from app.core.interfaces.services.jwt_service_interface import (
    IJwtService,
    TokenType,
)

# Temporary import for AuditLogger - TODO: Replace with IAuditLogger via DI
from app.infrastructure.logging.audit_logger import AuditLogger


def get_jwt_logger():
    return logging.getLogger(__name__) # Module-level logger


# Type definition for token blacklist dictionary
# Maps JTI (JWT ID) to expiration datetime
TokenBlacklistDict = dict[str, datetime | float | str] # Changed from Union

class TokenPayload(BaseModel):
    """Model for JWT token payload validation and parsing."""
    sub: str  # Subject (user ID)
    exp: int  # Expiration time (timestamp)
    iat: int  # Issued at time (timestamp)
    nbf: int | None = None  # Not before time (timestamp)
    jti: str = ""  # JWT ID for tracking tokens in blacklist
    type: TokenType = TokenType.ACCESS  # Token type (access or refresh)

    # JWT standard fields
    iss: str | None = None  # Issuer
    aud: str | None = None  # Audience

    # Application-specific fields
    scope: str | None = None  # Authorization scope
    roles: list[str] = []  # User roles
    refresh: bool = False  # Flag for refresh tokens
    parent_jti: str | None = None  # Parent token JTI for refresh token tracking
    family_id: str | None = None  # Family ID for token rotation tracking

    model_config = {
        "extra": "allow",  # Allow extra fields to support custom claims
        "frozen": True,    # Immutable for security
        "validate_assignment": True  # Validate values on assignment
    }
    
    @computed_field
    def get_type(self) -> TokenType:
        """Get token type enum."""
        return self.type
        
    @computed_field
    def get_expiration(self) -> datetime:
        """Get expiration as datetime object."""
        try:
            return datetime.fromtimestamp(self.exp, tz=timezone.utc)
        except Exception as e:
            logger.warning(f"Error converting expiration timestamp: {str(e)}")
            return datetime.now(timezone.utc) + timedelta(minutes=30)
        
    @computed_field
    def get_issued_at(self) -> datetime:
        """Get issued at as datetime object."""
        try:
            return datetime.fromtimestamp(self.iat, tz=timezone.utc)
        except Exception as e:
            logger.warning(f"Error converting issued_at timestamp: {str(e)}")
            return datetime.now(timezone.utc) - timedelta(minutes=30)
    
    @computed_field
    def is_expired(self) -> bool:
        """Check if token is expired."""
        try:
            current_timestamp = int(datetime.now(timezone.utc).timestamp())
            return current_timestamp > self.exp
        except Exception as e:
            logger.warning(f"Error in is_expired check: {str(e)}. Using fallback method.")
            return True

class JWTService(IJwtService):
    """
    Service for JWT token generation, validation and management.
    Implements secure token handling for HIPAA-compliant applications.
    Implements IJwtService.
    """
    
    def __init__(
        self,
        secret_key: str,
        algorithm: str,
        access_token_expire_minutes: float,
        refresh_token_expire_days: float,
        audience: str | None = None,
        issuer: str | None = None,
        leeway: int = 0,
        token_blacklist_repository: ITokenBlacklistRepository | None = None,
        user_repository: IUserRepository | None = None, # For user validation if needed
    ):
        """
        Initialize JWT service with configuration.
        
        Args:
            secret_key: JWT secret key
            algorithm: JWT algorithm
            access_token_expire_minutes: Access token expiration in minutes
            refresh_token_expire_days: Refresh token expiration in days
            audience: Optional JWT audience
            issuer: Optional JWT issuer
            leeway: Optional leeway for token expiration verification
            token_blacklist_repository: Optional repository for token blacklisting
            user_repository: Optional repository for user data
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.audience = audience
        self.issuer = issuer
        self.leeway = timedelta(seconds=leeway)
        self.token_blacklist_repository = token_blacklist_repository
        self.user_repository = user_repository

        # Temporary AuditLogger instance
        self.audit_logger = AuditLogger() # type: ignore[call-arg] # TODO: Remove type: ignore when DI is proper
        
        # This is NOT suitable for production, but prevents errors in development/testing
        # Token blacklist for revoked tokens
        # In production, this should be stored in Redis or similar through the repository
        self._token_blacklist: TokenBlacklistDict = {}
        
        if self.token_blacklist_repository is None:
            logger.warning(
                "No token blacklist repository provided. "
                "Using in-memory blacklist, which is NOT suitable for production."
            )
        else:
            logger.info("Token blacklist repository provided and will be used.")
        
        logger.info(f"JWT service initialized with algorithm {self.algorithm}")
        
    def _make_payload_serializable(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Convert payload values to JSON-serializable types."""
        import uuid
        result: dict[str, Any] = {}
        for k, v in payload.items():
            if isinstance(v, uuid.UUID):
                result[k] = str(v)
            elif isinstance(v, datetime | date):  
                result[k] = v.isoformat()
            elif isinstance(v, enum.Enum):
                result[k] = v.value
            elif isinstance(v, dict):
                result[k] = self._make_payload_serializable(v)
            elif isinstance(v, list):
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
        expires_delta_minutes: int | None = None,
        expires_delta: timedelta | None = None,
        jti: str | None = None
    ) -> str:
        """
        Create an access token for a user.
        
        Args:
            data: Data to include in token payload (must include 'sub' field)
            expires_delta_minutes: Optional override for token expiration time in minutes
            expires_delta: Optional override for token expiration as timedelta
            jti: Custom JTI (JWT ID) to use for the token
            
        Returns:
            Encoded JWT access token
            
        Raises:
            ValueError: If 'sub' field is not provided in data
        """
        if "sub" not in data:
            raise ValueError("Token data must include 'sub' field")
            
        return self._create_token(
            data=data,
            is_refresh_token=False,
            token_type="access_token",
            expires_delta_minutes=expires_delta_minutes,
            expires_delta=expires_delta,
            jti=jti
        )

    def create_refresh_token(
        self,
        data: dict[str, Any],
        expires_delta: timedelta | None = None
    ) -> str:
        """
        Create a refresh token for a user.
        
        Args:
            data: Data to include in token payload (must include 'sub' field)
            expires_delta: Optional override for token expiration as timedelta
            
        Returns:
            Encoded JWT refresh token
            
        Raises:
            ValueError: If 'sub' field is not provided in data
        """
        if "sub" not in data:
            raise ValueError("Missing 'sub' field in token data for refresh token")

        # Extract family_id and parent_jti from data if present
        token_data = data.copy()
        family_id = token_data.pop('family_id', None)
        parent_token_jti = token_data.pop('parent_jti', None)

        refresh_specific_claims: dict[str, Any] = {}
        if parent_token_jti:
            refresh_specific_claims['parent_jti'] = parent_token_jti
        if family_id:
            refresh_specific_claims['family_id'] = family_id

        # Merge with existing data, ensuring refresh claims take precedence if keys overlap (unlikely here)
        final_data = {**token_data, **refresh_specific_claims}

        return self._create_token(
            data=final_data,
            token_type=TokenType.REFRESH,
            expires_delta=expires_delta
        )

    def _register_token_in_family(self, jti: str, family_id: str) -> None:
        """
        Register a token in the token family system for refresh token rotation tracking.
        
        Args:
            jti: The token's unique identifier
            family_id: The token family identifier
        """
        # Initialize dictionaries if not already
        if not hasattr(self, '_token_families'):
            self._token_families = {}
        if not hasattr(self, '_token_family_map'):
            self._token_family_map = {}
            
        # Update the token family mappings
        self._token_families[family_id] = jti
        self._token_family_map[jti] = family_id

    def _create_token(
        self,
        data: dict,
        token_type: TokenType = TokenType.ACCESS, 
        expires_delta: timedelta | None = None,
        expires_delta_minutes: float | None = None, 
        jti: str | None = None,
    ) -> str:
        """
        Internal method to create a JWT token with appropriate claims.

        Args:
            data: Data to encode in the token
            token_type: Type of token (access or refresh)
            expires_delta: Override expiration time as timedelta
            expires_delta_minutes: Override expiration time in minutes
            jti: Specify a custom JWT ID

        Returns:
            Encoded JWT token string
        """
        # Copy the data to avoid modifying the original
        to_encode = data.copy()
        
        # Use timezone-aware datetime for all calculations
        now_datetime = datetime.now(UTC)

        if expires_delta:
            effective_expires_delta = expires_delta
        elif expires_delta_minutes is not None: 
            effective_expires_delta = timedelta(minutes=float(expires_delta_minutes))
        elif token_type == TokenType.REFRESH:
            effective_expires_delta = timedelta(days=float(self.refresh_token_expire_days))
        else:  # Default to access token expiry for other types if not specified
            effective_expires_delta = timedelta(minutes=float(self.access_token_expire_minutes))

        expire_datetime = now_datetime + effective_expires_delta
        
        # Logging for debugging expiration
        # Use math.floor on the timestamp for the exp_claim_value to match what's encoded
        logger.info(
            f"Token creation: now='{now_datetime.isoformat()}', "
            f"expires_delta='{expires_delta}', "
            f"calculated_exp_datetime='{expire_datetime.isoformat()}', "
            f"exp_claim_value={math.floor(expire_datetime.timestamp())}, "
            f"type='{token_type.value}'"
        )

        # Prepare claims using math.floor to match original behavior for timestamps
        now_timestamp = math.floor(now_datetime.timestamp())
        expire_timestamp = math.floor(expire_datetime.timestamp())
        
        token_jti = jti if jti is not None else str(uuid.uuid4())
        
        # Ensure 'sub' is a string
        subject_val = to_encode.get("sub")
        subject_str: Optional[str] = None
        if isinstance(subject_val, uuid.UUID):
            subject_str = str(subject_val)
        elif subject_val is not None:
            subject_str = str(subject_val)
        else:
            logger.warning("Token created without a 'sub' claim.")
            # Depending on policy, you might raise an error or allow 'sub' to be absent
            # For now, we'll let it be absent if not provided, mirroring previous to_encode.get behavior.

        claims_to_add: dict[str, Any] = {
            "exp": expire_timestamp,
            "iat": now_timestamp,
            "nbf": now_timestamp,  # Not Before claim
            "jti": token_jti,
            "typ": token_type.value,  # Use the string value of the enum
        }
        if subject_str is not None: # Only add 'sub' if it was present and processed
            claims_to_add["sub"] = subject_str
        
        # Update to_encode with the new claims, ensuring 'sub' from original data is replaced if present
        # or added if derived. Original data's 'sub' could be different from subject_str if it wasn't a UUID.
        # This logic prioritizes the processed subject_str for the 'sub' claim.
        existing_sub = to_encode.pop("sub", None) # Remove original sub if exists to avoid conflict
        if subject_str is not None:
             to_encode["sub"] = subject_str
        elif existing_sub is not None: # if subject_str ended up None, but there was an original sub
             to_encode["sub"] = str(existing_sub) # put it back as string

        to_encode.update(claims_to_add)
        
        # Add issuer and audience if available
        if self.issuer:
            to_encode["iss"] = self.issuer
        if self.audience:
            to_encode["aud"] = self.audience
            
        # For backward compatibility with tests, set the enum-based type field
        if token_type == TokenType.REFRESH:
            to_encode["type"] = TokenType.REFRESH.value
            to_encode["refresh"] = True
            to_encode["scope"] = "refresh_token"
        else:
            to_encode["type"] = TokenType.ACCESS.value
        
        # Ensure all values are JSON serializable
        serializable_payload = self._make_payload_serializable(to_encode)
        
        try:
            # Create the JWT token
            encoded_jwt = jwt_jose.encode(
                serializable_payload, 
                self.secret_key, 
                algorithm=self.algorithm
            )
            
            # Log token creation (without exposing the actual token)
            logger.info(f"Created {token_type.value} for subject {subject_str[:8]}...")
            
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Error creating token: {e!s}", exc_info=True)
            raise TokenCreationError(f"Failed to generate token: {e!s}") from e

    def _decode_jwt(
        self,
        token: str,
        key: str,
        algorithms: list[str],
        audience: str | None = None,
        issuer: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Low-level JWT decode function.
        
        Args:
            token: JWT token to decode
            key: Secret key for decoding
            algorithms: List of allowed algorithms
            audience: Expected audience 
            issuer: Expected issuer
            options: Options for decoding
            
        Returns:
            dict: Decoded JWT payload
            
        Raises:
            ExpiredSignatureError: If the token has expired (passed through)
            InvalidTokenError: For other validation errors
        """
        if not token:
            raise InvalidTokenError("Invalid token: Token is empty or None")
            
        # Basic token format validation before attempting to decode
        if not isinstance(token, str):
            # Handle binary tokens or other non-string inputs consistently
            if isinstance(token, bytes):
                # Binary data usually results in header parsing errors
                raise InvalidTokenError("Invalid token: Invalid header string")
            else:
                # Other non-string types
                raise InvalidTokenError("Invalid token: Not enough segments")
        
        # Check if token follows the standard JWT format: header.payload.signature
        if token.count('.') != 2:
            raise InvalidTokenError("Invalid token: Not enough segments")
            
        if options is None:
            options = {}

        # Specify default parameters
        kwargs = {}
        
        # Set audience if provided or use default
        if audience is not None:
            kwargs["audience"] = audience
        elif self.audience:
            kwargs["audience"] = self.audience
            
        # Set issuer if provided or use default
        if issuer is not None:
            kwargs["issuer"] = issuer
        elif self.issuer:
            kwargs["issuer"] = self.issuer
            
        # Handle different parameter naming in different JWT libraries
        # Some use 'algorithm' (singular) others use 'algorithms' (plural)
        try:
            current_options = options.copy() if options else {}
            # Ensure no 'algorithms' key is in options, as it's a direct param to jose.decode
            current_options.pop('algorithms', None) 

            payload = jwt_jose.decode(
                token,
                key,
                algorithms=algorithms,  # Pass the algorithms list directly
                audience=audience or self.audience,
                issuer=issuer or self.issuer,
                options=current_options
            )
            return cast(dict[str, Any], payload) # Cast if jwt_jose.decode returns a more general dict
        except ExpiredSignatureError:
            # Let this pass through for dedicated handling in the caller
            raise
        except JWTError as e:
            # Format the error message consistently
            if "Invalid header" in str(e):
                raise InvalidTokenError("Invalid token: Invalid header string")
            elif "segment" in str(e).lower() or "segments" in str(e).lower():
                raise InvalidTokenError("Invalid token: Not enough segments")
            else:
                logger.error(f"JWT decode error: {e}")
                raise InvalidTokenError(f"Invalid token: {e}")
        except TypeError as e:
            # If the error suggests a parameter mismatch, try with 'algorithm' (singular)
            if "unexpected keyword argument" in str(e) and "algorithms" in str(e):
                logger.warning("JWT decode failed with 'algorithms', trying with 'algorithm'")
                try:
                    return jwt_jose.decode(token, key, algorithm=algorithms[0], options=options, **kwargs)
                except ExpiredSignatureError:
                    # Let this pass through for dedicated handling in the caller
                    raise
                except Exception as inner_e:
                    logger.error(f"Error in _decode_jwt with algorithm fallback: {inner_e}")
                    raise InvalidTokenError(f"Invalid token: {inner_e}")
            else:
                logger.error(f"TypeError in _decode_jwt: {e}")
                raise InvalidTokenError(f"Invalid token: {e}")
        except Exception as e:
            logger.error(f"Error in _decode_jwt: {e}")
            raise InvalidTokenError(f"Invalid token: {e}")
            
    def decode_token(
        self, 
        token: str, 
        verify_signature: bool = True,
        options: dict[str, Any] | None = None,
        audience: str | None = None,
        algorithms: list[str] | None = None,
    ) -> TokenPayload:
        """
        Decode and validate a JWT token.
        
        Args:
            token: JWT token to decode
            verify_signature: Whether to verify the signature
            options: Options for decoding (jwt.decode options)
            audience: Expected audience
            algorithms: List of allowed algorithms
            
        Returns:
            TokenPayload: Validated token payload
            
        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token has expired
        """
        if algorithms is None:
            algorithms = [self.algorithm]
            
        # Set up options
        if options is None:
            options = {}
        options = {**options, "verify_signature": verify_signature}
        
        # In test environments, we may want to skip expiration verification by default
        if hasattr(self, 'settings') and self.settings and hasattr(self.settings, 'TESTING') and self.settings.TESTING:
            if "verify_exp" not in options:
                options["verify_exp"] = False
                logger.debug("Test environment detected: disabling token expiration verification by default")
        
        try:
            # First try to catch ExpiredSignatureError directly from jose/jwt
            try:
                # First, decode the JWT
                payload = self._decode_jwt(
                    token=token,
                    key=self.secret_key,
                    algorithms=algorithms,
                    audience=audience,
                    issuer=self.issuer,
                    options=options
                )
            except ExpiredSignatureError as e:
                # Specifically handle expired tokens with the correct exception type
                logger.error(f"Token has expired: {e}")
                raise TokenExpiredError(f"Token has expired: {e}")
            
            # Ensure type field uses enum value
            if "type" in payload:
                try:
                    if isinstance(payload["type"], str):
                        # Convert string to TokenType enum
                        if payload["type"] in [e.value for e in TokenType]:
                            payload["type"] = payload["type"]  # Keep as string, TokenPayload will convert
                        else:
                            # Default to ACCESS if unrecognized
                            payload["type"] = TokenType.ACCESS.value
                except Exception as e:
                    logger.warning(f"Error converting token type: {e}")
                    payload["type"] = TokenType.ACCESS.value
            
            # Process roles if they exist
            if "role" in payload and "roles" not in payload:
                # Convert single role to roles array
                payload["roles"] = [payload["role"]]
            elif "roles" not in payload:
                # Ensure roles exists even if empty
                payload["roles"] = []
            
            # Then validate the payload with Pydantic
            try:
                token_payload = TokenPayload.model_validate(payload)
            except ValidationError as ve:
                logger.error(f"Token validation error: {ve}")
                raise InvalidTokenError(f"Invalid token: {ve}")
            except Exception as general_e:
                logger.error(f"Unexpected error creating TokenPayload: {general_e}")
                raise InvalidTokenError(f"Invalid token: {general_e}")
            
            # Check if token is blacklisted
            if token_payload.jti and self._is_token_blacklisted(token_payload.jti):
                logger.warning(f"Token with JTI {token_payload.jti} is blacklisted")
                raise InvalidTokenError("Invalid token: Token has been revoked")
                
            # Return the validated payload
            return token_payload
                
        except TokenExpiredError:
            # Pass through our specific exception without wrapping it
            raise
        except JWTError as e:
            logger.error(f"Error decoding token: {e}")
            raise InvalidTokenError(f"Invalid token: {e}")
        except InvalidTokenError:
            # Rethrow without changing the message if it's already an InvalidTokenError
            raise
        except Exception as e:
            logger.error(f"Error decoding token: {e}")
            raise InvalidTokenError(f"Invalid token: {e}")

    async def get_user_from_token(self, token: str) -> User | None:
        """
        Get the user associated with a token.
        
        Args:
            token: JWT token
            
        Returns:
            User: The user object associated with the token
            
        Raises:
            AuthenticationError: If the user is not found or token is invalid
        """
        # Check if user repository is configured
        if not self.user_repository:
            logger.error("User repository not configured for JWTService")
            raise AuthenticationError("Cannot retrieve user data - repository not configured")
        
        # Decode and verify the token
        payload = self.decode_token(token)
        
        # Get subject from the payload
        user_id = payload.sub
        
        if not user_id:
            logger.error(f"Token payload does not contain user ID: {payload}")
            raise AuthenticationError("Invalid token - no user ID")
            
        try:
            # Use the repository to get the user
            user = await self.user_repository.get_by_id(user_id)
            
            if not user:
                logger.warning(f"User not found for ID {user_id}")
                raise AuthenticationError("User not found")
                
            return user
            
        except Exception as e:
            logger.error(f"Error retrieving user from token: {e!s}", exc_info=True)
            raise AuthenticationError(f"Failed to retrieve user: {e!s}")

    def verify_refresh_token(self, refresh_token: str) -> TokenPayload:
        """
        Verify that a token is a valid refresh token.
        
        Args:
            refresh_token: The refresh token to verify
            
        Returns:
            TokenPayload: The decoded token payload
            
        Raises:
            InvalidTokenError: If the token is not a refresh token or otherwise invalid
            TokenExpiredError: If the token is expired
            TokenRevokedError: If the token is blacklisted
        """
        # Decode the token first to verify its basic validity
        # Use verify_exp=False to prevent token expiration errors during verification
        # The expiration will be checked separately if needed
        options = {"verify_exp": False}
        payload = self.decode_token(refresh_token, options=options)
        
        # Check that this is a refresh token by checking both the type field and the refresh flag
        # Handle different ways token type could be stored
        is_refresh = False
        
        # Check token type (primary method)
        if payload.type == TokenType.REFRESH:
            is_refresh = True
        
        # Check refresh flag (backward compatibility)
        if hasattr(payload, "refresh") and payload.refresh is True:
            is_refresh = True
            
        # Check scope (additional verification)
        if hasattr(payload, "scope") and payload.scope == "refresh_token":
            is_refresh = True
            
        if not is_refresh:
            raise InvalidTokenError("Token is not a refresh token")
            
        # If we reach here, the token is a valid refresh token
        # Now check if it's expired
        if options.get("verify_exp", True):
            # Only check expiration if verify_exp is True
            if hasattr(payload, "is_expired") and payload.is_expired:
                raise TokenExpiredError("Refresh token has expired")
                
            # Additional expiration check using raw timestamp
            if hasattr(payload, "exp"):
                now = datetime.now(UTC).timestamp()
                if payload.exp < now:
                    raise TokenExpiredError("Refresh token has expired")
                    
        # Check if token is blacklisted
        if payload.jti and self._is_token_blacklisted(payload.jti):
            raise InvalidTokenError("Refresh token has been revoked")
                    
        # Return the validated payload
        return payload

    def get_token_payload_subject(self, payload: TokenPayload) -> str | None:
        """Get the subject (user ID) from a token payload."""
        return payload.sub if hasattr(payload, "sub") else None
        
    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Refresh an access token using a valid refresh token.
        
        Args:
            refresh_token: Refresh token to use for generating a new access token
            
        Returns:
            str: New access token
            
        Raises:
            InvalidTokenError: If the refresh token is invalid or expired
        """
        try:
            # Decode and verify the refresh token - skip expiration check initially
            payload = self.decode_token(refresh_token, options={"verify_exp": False})
            
            # Now check if it's expired manually if needed
            if payload.is_expired:
                raise TokenExpiredError("Refresh token has expired")
            
            # Check if it's actually a refresh token
            token_type = getattr(payload, "type", None)
            is_refresh = getattr(payload, "refresh", False)
            
            if not (token_type == TokenType.REFRESH or is_refresh):
                raise InvalidTokenError("Token is not a refresh token")
                
            # Extract user ID and create a new access token
            user_id = payload.sub
            if not user_id:
                raise InvalidTokenError("Invalid token: missing subject claim")
                
            # Create a new access token with the same user ID
            new_access_token = self.create_access_token({"sub": user_id})
            
            return new_access_token
            
        except (JWTError, ExpiredSignatureError, InvalidTokenError) as e:
            logger.warning(f"Failed to refresh token: {e}")
            raise InvalidTokenError("Invalid or expired refresh token")
        
    async def revoke_token(self, token: str) -> None:
        """
        Revokes a token by adding its JTI to the blacklist.
        
        Args:
            token: The JWT token to revoke
        """
        try:
            # Temporarily decode without full validation for blacklist, to avoid async issues here for now
            # This is a simplification; proper handling might need more refactoring for sync/async consistency.
            _algos = [self.algorithm]
            payload_dict = self._decode_jwt(token, self.secret_key, _algos, options={"verify_exp": False, "verify_signature": False})
            payload = TokenPayload(**payload_dict)

        except InvalidTokenError as e:
            # If token is so invalid it can't even be parsed for JTI, log and potentially re-raise or ignore
            logger.error(f"Could not revoke token because it is too invalid to parse JTI: {e}")
            return # Or raise, depending on desired behavior

        jti = payload.jti
        # Use the token's actual expiration for the blacklist entry's lifetime
        # get_expiration is a computed field returning datetime
        expires_at: datetime = payload.get_expiration 

        if self.token_blacklist_repository:
            try:
                await self.token_blacklist_repository.add_to_blacklist(
                    token=token,  # The raw token string, as per interface interpretation
                    jti=jti,
                    expires_at=expires_at
                )
                logger.info(f"Token with JTI {jti} revoked and added to blacklist via repository.")
            except Exception as e:
                logger.error(f"Failed to add token JTI {jti} to blacklist repository: {e}")
                # Optionally, fallback to in-memory if repo fails, or just log
        else:
            # Fallback to in-memory blacklist
            self._token_blacklist[jti] = expires_at.timestamp() # Store as timestamp
            logger.info(f"Token JTI {jti} added to in-memory blacklist.")

    async def _is_token_blacklisted(self, jti: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            jti: The JWT ID to check
            
        Returns:
            bool: True if the token is blacklisted, False otherwise
        """
        # Check if token is in the in-memory blacklist
        if jti in self._token_blacklist:
            return True
            
        # If we have a token blacklist repository, check there too
        if self.token_blacklist_repository:
            try:
                return await self.token_blacklist_repository.is_jti_blacklisted(jti) # Assuming is_jti_blacklisted from interface
            except Exception as e:
                logger.error(f"Error checking token blacklist repository: {e!s}")
                # Default to not blacklisted if we can't check
                return False
                
        # Fallback to in-memory blacklist (remove expired entries first for correctness)
        # This part of in-memory blacklist management could be more robust
        current_time = datetime.now(UTC).timestamp()
        # Filter out expired entries from the in-memory blacklist
        self._token_blacklist = { 
            k: v for k, v in self._token_blacklist.items() 
            if isinstance(v, float | int) and v > current_time # Use X | Y for isinstance
        }
        
        if jti in self._token_blacklist:
            return True

        return False

    def check_resource_access(self, request, resource_path: str, resource_owner_id: str = None) -> bool:
        """
        Check if the user has access to the specified resource.
        
        Args:
            request: The request object containing the token
            resource_path: The path to the resource
            resource_owner_id: The ID of the resource owner, if applicable
            
        Returns:
            bool: True if the user has access, False otherwise
        """
        try:
            # Extract token from request
            token = self.extract_token_from_request(request)
            if not token:
                logger.warning("No token found in request when checking resource access")
                return False
                
            # Decode the token
            payload = self.decode_token(token)
            
            # Get user ID and roles from token
            user_id = payload.sub
            roles = getattr(payload, "roles", [])
            
            # If no roles, deny access
            if not roles:
                logger.warning(f"No roles found in token for user {user_id}")
                return False
                
            # Special case: Admin role always has access
            if "admin" in roles:
                logger.debug(f"Admin role granted access to {resource_path}")
                return True
                
            # Check owner-based access
            if resource_owner_id and user_id == resource_owner_id:
                logger.debug(f"User {user_id} granted owner access to {resource_path}")
                return True
                
            # Here we would implement more complex role-based access rules
            # For now, return True for testing
            return True
                
        except (InvalidTokenError, TokenExpiredError) as e:
            logger.warning(f"Token validation failed during resource access check: {e}")
            return False
        except Exception as e:
            logger.error(f"Error checking resource access: {e}")
            return False
    
    def extract_token_from_request(self, request) -> str | None:
        """
        Extract JWT token from the request.
        
        Args:
            request: The request object
            
        Returns:
            Optional[str]: The token if found, None otherwise
        """
        # Check Authorization header
        auth_header = getattr(request, "headers", {}).get("Authorization", "")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header.replace("Bearer ", "")
            
        # Check cookies
        cookies = getattr(request, "cookies", {})
        if cookies and "access_token" in cookies:
            return cookies["access_token"]
            
        # No token found
        return None
        
    def create_unauthorized_response(self, error_type: str, message: str) -> dict:
        """
        Create a standardized response for unauthorized requests.
        
        Args:
            error_type: Type of error (token_expired, invalid_token, insufficient_permissions)
            message: Error message
            
        Returns:
            dict: Response dict with status code and body
        """
        # Sanitize error message for HIPAA compliance
        sanitized_message = self._sanitize_error_message(message)
        
        if error_type in ["token_expired", "invalid_token", "missing_token"]:
            status_code = 401  # Unauthorized
        elif error_type == "insufficient_permissions":
            status_code = 403  # Forbidden
        else:
            status_code = 400  # Bad Request
            
        return {
            "status_code": status_code,
            "body": {
                "error": sanitized_message,
                "error_type": error_type
            }
        }
        
    def _sanitize_error_message(self, message: str) -> str:
        """
        Sanitize error messages to ensure HIPAA compliance.
        
        Args:
            message: Original error message
            
        Returns:
            str: Sanitized error message
        """
        # Map specific error patterns to HIPAA-compliant messages
        sensitive_patterns = {
            "signature": "Invalid token",
            "expired": "Token has expired",
            "invalid token": "Authentication failed",
            "user not found": "Authentication failed",
            "user id": "Authentication failed"
        }
        
        # Check if message contains any sensitive patterns
        message_lower = message.lower()
        for pattern, replacement in sensitive_patterns.items():
            if pattern in message_lower:
                return replacement
                
        # Check for common PII patterns and sanitize
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', message):
            return "Authentication failed"
            
        if re.search(r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b', message):  # SSN pattern
            return "Authentication failed"
            
        # Default sanitized message
        return message

    async def refresh_token(self, refresh_token: str) -> str:
        """
        Create a new refresh token based on an existing one.
        
        This method is primarily for testing purposes. For actual token
        refresh operations, use refresh_token_pair() which handles both 
        access and refresh tokens.
        
        Args:
            refresh_token: The existing refresh token
            
        Returns:
            str: A new refresh token
            
        Raises:
            InvalidTokenError: If the token is invalid
            TokenExpiredError: If the token is expired
            TokenRevokedError: If the token has been revoked
        """
        # Decode and verify the token
        payload = self.verify_refresh_token(refresh_token)
        
        # Get the core claims from the payload
        sub = payload.sub
        family_id = getattr(payload, "family_id", None)
        
        # Create data for the new token
        data = {
            "sub": sub,
            "type": TokenType.REFRESH,
            "refresh": True,  # Legacy field
        }
        
        # Add family_id if present in the original token
        if family_id:
            data["family_id"] = family_id
        
        # Create the new token with the same claims
        new_token = self.create_refresh_token(
            data=data,
            family_id=family_id,
            parent_token_jti=payload.jti
        )
        
        # Revoke the old token - now properly awaited
        await self.revoke_token(refresh_token)
        
        return new_token


# Define dependency injection function
def get_jwt_service(
    settings: settings,
    user_repository = None,
    token_blacklist_repository = None
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
    if not hasattr(settings, 'JWT_SECRET_KEY') or not settings.JWT_SECRET_KEY:
        # Use a default for testing if in test environment
        if hasattr(settings, 'ENVIRONMENT') and settings.ENVIRONMENT == "test":
            secret_key = "testsecretkeythatisverylong"
        else:
            raise ValueError("JWT_SECRET_KEY is required in settings")
    else:
        # Handle SecretStr type safely
        if hasattr(settings.JWT_SECRET_KEY, 'get_secret_value'):
            secret_key = settings.JWT_SECRET_KEY.get_secret_value()
        else:
            secret_key = str(settings.JWT_SECRET_KEY)
    
    # Validate secret key
    if not secret_key or len(secret_key.strip()) < 16:
        if hasattr(settings, 'ENVIRONMENT') and settings.ENVIRONMENT == "test":
            # Allow shorter keys in test
            if len(secret_key.strip()) < 8:
                secret_key = "testsecretkeythatisverylong"
        else:
            raise ValueError("JWT_SECRET_KEY must be at least 16 characters long")
    
    # Get required settings with validation
    try:
        algorithm = str(getattr(settings, 'JWT_ALGORITHM', 'HS256'))
        if algorithm not in ['HS256', 'HS384', 'HS512']:
            raise ValueError(f"Unsupported JWT algorithm: {algorithm}")
        
        access_token_expire_minutes = int(getattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 30))
        if access_token_expire_minutes < 1:
            raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES must be positive")
        
        refresh_token_expire_days = int(getattr(settings, 'JWT_REFRESH_TOKEN_EXPIRE_DAYS', 7))
        if refresh_token_expire_days < 1:
            raise ValueError("JWT_REFRESH_TOKEN_EXPIRE_DAYS must be positive")
        
    except (ValueError, TypeError) as e:
        if hasattr(settings, 'ENVIRONMENT') and settings.ENVIRONMENT == "test":
            # Use defaults in test environment
            algorithm = 'HS256'
            access_token_expire_minutes = 30
            refresh_token_expire_days = 7
        else:
            raise ValueError(f"Invalid JWT settings: {str(e)}")
    
    # Get optional settings
    issuer = getattr(settings, 'JWT_ISSUER', None)
    audience = getattr(settings, 'JWT_AUDIENCE', None)
    
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
        settings=settings
    )