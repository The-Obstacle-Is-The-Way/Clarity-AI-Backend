"""
Interface definition for Authentication Service.

Defines the contract for authentication, user identity and token management
following HIPAA-compliant security practices in a clean architecture design.
"""

from abc import ABC, abstractmethod
from typing import Any

# Attempt to import User, handle potential circular dependency gracefully
try:
    from app.domain.entities.user import User
except ImportError:
    # Use Any as a fallback if User cannot be imported
    from typing import Any
    User = Any


class IAuthenticationService(ABC):
    """
    Interface for authentication service.
    
    Defines methods for user authentication, token creation and validation
    ensuring a consistent contract for all implementations.
    """
    
    @abstractmethod
    async def authenticate_user(self, username: str, password: str) -> User | None:
        """
        Authenticate a user with username and password.
        
        Args:
            username: The user's username
            password: The user's plaintext password
            
        Returns:
            User entity if authentication successful, None otherwise
            
        Raises:
            AuthenticationError: For specific authentication issues
        """
        pass
    
    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> User:
        """
        Get a user by their ID.
        
        Args:
            user_id: User's unique identifier
            
        Returns:
            User domain entity
            
        Raises:
            EntityNotFoundError: If user not found
        """
        pass
    
    @abstractmethod
    def create_access_token(self, user: User) -> str:
        """
        Create an access token for a user.
        
        Args:
            user: User domain entity
            
        Returns:
            JWT access token
        """
        pass
    
    @abstractmethod
    def create_refresh_token(self, user: User) -> str:
        """
        Create a refresh token for a user.
        
        Args:
            user: User domain entity
            
        Returns:
            JWT refresh token
        """
        pass
    
    @abstractmethod
    def create_token_pair(self, user: User) -> dict[str, str]:
        """
        Create both access and refresh tokens.
        
        Args:
            user: User domain entity
            
        Returns:
            Dictionary with access_token and refresh_token
        """
        pass
    
    @abstractmethod
    def refresh_token(self, refresh_token: str) -> dict[str, str]:
        """
        Create a new access token using a refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Dictionary with new access_token and existing refresh_token
        """
        pass
