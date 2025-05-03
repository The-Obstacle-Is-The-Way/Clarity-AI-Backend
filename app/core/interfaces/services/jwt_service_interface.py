"""
JWT service interface definition.

This module defines the abstract interface for JWT token operations,
following clean architecture principles with clear separation of concerns.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

from app.core.domain.entities.user import User


class JWTServiceInterface(ABC):
    """
    Abstract interface for JWT token services.
    
    This interface defines the contract for JWT token operations,
    allowing for different implementations while maintaining a
    consistent interface throughout the application.
    """
    
    @abstractmethod
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
        raise NotImplementedError
    
    @abstractmethod
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
        raise NotImplementedError
    
    @abstractmethod
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
        raise NotImplementedError
    
    @abstractmethod
    def generate_tokens_for_user(self, user: User) -> Dict[str, str]:
        """
        Generate both access and refresh tokens for a user.
        
        Args:
            user: The user entity to generate tokens for
            
        Returns:
            Dictionary with 'access_token' and 'refresh_token' keys
        """
        raise NotImplementedError
    
    @abstractmethod
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
        raise NotImplementedError
    
    @abstractmethod
    def verify_token(self, token: str) -> bool:
        """
        Verify a token's validity without fully decoding it.
        
        This is useful for quick validation checks.
        
        Args:
            token: The token to verify
            
        Returns:
            True if the token is valid, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    def get_token_expiration(self, token: str) -> Optional[datetime]:
        """
        Get the expiration time of a token.
        
        Args:
            token: The token to check
            
        Returns:
            The expiration datetime, or None if the token is invalid
        """
        raise NotImplementedError