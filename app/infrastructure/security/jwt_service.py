"""
JWT service implementation.

This module implements the JWTServiceInterface using production-ready
JWT handling with proper security practices for healthcare applications.
"""

from datetime import datetime, timedelta
import os
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from app.core.domain.entities.user import User
from app.core.errors.security_exceptions import InvalidCredentialsError, TokenExpiredError, TokenValidationError
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface


class JWTService(JWTServiceInterface):
    """
    Implementation of JWT token service using the jose library.
    
    This class provides secure JWT token generation and validation
    following HIPAA security standards for healthcare applications.
    """
    
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7
    ):
        """
        Initialize the JWT service with configuration.
        
        Args:
            secret_key: Secret key for signing tokens
            algorithm: JWT signing algorithm
            access_token_expire_minutes: Expiration time for access tokens
            refresh_token_expire_days: Expiration time for refresh tokens
        """
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._access_token_expire = timedelta(minutes=access_token_expire_minutes)
        self._refresh_token_expire = timedelta(days=refresh_token_expire_days)
    
    def create_access_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a new JWT access token.
        
        Args:
            data: The payload data to encode in the token
            expires_delta: Optional custom expiration time
            
        Returns:
            The encoded JWT token string
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or self._access_token_expire)
        
        # Add standard JWT claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        })
        
        # Encode and sign the token
        return jwt.encode(to_encode, self._secret_key, algorithm=self._algorithm)
    
    def create_refresh_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a new JWT refresh token.
        
        Args:
            data: The payload data to encode in the token
            expires_delta: Optional custom expiration time
            
        Returns:
            The encoded JWT refresh token string
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or self._refresh_token_expire)
        
        # Add standard JWT claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        })
        
        # Encode and sign the token
        return jwt.encode(to_encode, self._secret_key, algorithm=self._algorithm)
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.
        
        Args:
            token: The JWT token to decode
            
        Returns:
            The decoded token payload
            
        Raises:
            InvalidCredentialsError: If the token is invalid or expired
        """
        try:
            # Decode and verify the token
            payload = jwt.decode(token, self._secret_key, algorithms=[self._algorithm])
            
            # Check for token expiration (redundant, as jose already checks this)
            if "exp" in payload and datetime.fromtimestamp(payload["exp"]) < datetime.utcnow():
                raise TokenExpiredError("Token has expired")
                
            return payload
            
        except JWTError as e:
            # Convert jose exceptions to our domain exceptions
            if "expired" in str(e).lower():
                raise TokenExpiredError("Token has expired") from e
            else:
                raise TokenValidationError(f"Invalid token: {str(e)}") from e
    
    def generate_tokens_for_user(self, user: User) -> Dict[str, str]:
        """
        Generate both access and refresh tokens for a user.
        
        Args:
            user: The user entity to generate tokens for
            
        Returns:
            Dictionary with 'access_token' and 'refresh_token' keys
        """
        # Create the payload with user information
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "roles": [role.value for role in user.roles]
        }
        
        # Generate tokens
        access_token = self.create_access_token(payload)
        refresh_token = self.create_refresh_token(payload)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Create a new access token using a valid refresh token.
        
        Args:
            refresh_token: The refresh token to use
            
        Returns:
            A new access token
            
        Raises:
            InvalidCredentialsError: If the refresh token is invalid or expired
        """
        # Decode and validate the refresh token
        payload = self.decode_token(refresh_token)
        
        # Verify this is a refresh token
        if payload.get("type") != "refresh":
            raise TokenValidationError("Invalid token type")
        
        # Create a new access token with the same data
        # Remove token-specific fields
        token_data = {k: v for k, v in payload.items() 
                     if k not in ["exp", "iat", "type"]}
        
        return self.create_access_token(token_data)
    
    def verify_token(self, token: str) -> bool:
        """
        Verify a token's validity without fully decoding it.
        
        This is useful for quick validation checks.
        
        Args:
            token: The token to verify
            
        Returns:
            True if the token is valid, False otherwise
        """
        try:
            self.decode_token(token)
            return True
        except InvalidCredentialsError:
            return False
    
    def get_token_expiration(self, token: str) -> Optional[datetime]:
        """
        Get the expiration time of a token.
        
        Args:
            token: The token to check
            
        Returns:
            The expiration datetime, or None if the token is invalid
        """
        try:
            payload = self.decode_token(token)
            if "exp" in payload:
                return datetime.fromtimestamp(payload["exp"])
            return None
        except InvalidCredentialsError:
            return None


def get_jwt_service() -> JWTServiceInterface:
    """
    Factory function to create a JWTService instance.
    
    This function allows for dependency injection in FastAPI.
    
    Returns:
        An instance of JWTServiceInterface
    """
    # Get settings from environment or config
    # For test collection, use a fixed value
    secret_key = os.getenv("JWT_SECRET_KEY", "TESTSECRETKEYTESTSECRETKEYTESTSECRETKEY")
    algorithm = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    return JWTService(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days
    )