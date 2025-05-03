"""
Authentication service interface definition.

This module defines the abstract interface for the authentication service
following clean architecture principles, ensuring proper separation of concerns
and dependency inversion.
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple

from app.core.domain.entities.user import User


class AuthServiceInterface(ABC):
    """
    Abstract interface for authentication services.
    
    This interface defines the contract for authentication operations,
    allowing for different implementations (e.g., JWT, OAuth) while
    maintaining consistent usage throughout the application.
    """
    
    @abstractmethod
    async def authenticate_user(self, username_or_email: str, password: str) -> Optional[User]:
        """
        Authenticate a user with username/email and password.
        
        Args:
            username_or_email: The username or email address
            password: The plaintext password to verify
            
        Returns:
            Authenticated User entity if successful, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: The plaintext password to verify
            hashed_password: The stored password hash
            
        Returns:
            True if the password matches the hash, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def hash_password(self, password: str) -> str:
        """
        Hash a password securely.
        
        Args:
            password: The plaintext password to hash
            
        Returns:
            The secure password hash
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_password_hash(self, password: str) -> str:
        """
        Get a password hash using the configured algorithm.
        
        Args:
            password: The plaintext password to hash
            
        Returns:
            The password hash
        """
        raise NotImplementedError
    
    @abstractmethod
    async def change_password(self, user: User, current_password: str, new_password: str) -> Tuple[bool, Optional[str]]:
        """
        Change a user's password after verifying the current password.
        
        Args:
            user: The user entity
            current_password: The current plaintext password
            new_password: The new plaintext password
            
        Returns:
            Tuple of (success, error_message)
        """
        raise NotImplementedError
    
    @abstractmethod
    async def reset_password(self, user: User, token: str, new_password: str) -> Tuple[bool, Optional[str]]:
        """
        Reset a user's password using a reset token.
        
        Args:
            user: The user entity
            token: The password reset token
            new_password: The new plaintext password
            
        Returns:
            Tuple of (success, error_message)
        """
        raise NotImplementedError
    
    @abstractmethod
    async def generate_reset_token(self, user: User) -> str:
        """
        Generate a password reset token for a user.
        
        Args:
            user: The user entity
            
        Returns:
            The generated reset token
        """
        raise NotImplementedError
    
    @abstractmethod
    async def verify_mfa(self, user: User, token: str) -> bool:
        """
        Verify a multi-factor authentication token.
        
        Args:
            user: The user entity
            token: The MFA token to verify
            
        Returns:
            True if the token is valid, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def generate_mfa_secret(self) -> str:
        """
        Generate a new MFA secret for a user.
        
        Returns:
            The generated MFA secret
        """
        raise NotImplementedError