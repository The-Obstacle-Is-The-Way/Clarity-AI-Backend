"""
Password handler interface definition.

This module defines the interface for password handling services, ensuring proper
abstraction between the application layer and concrete infrastructure implementations.
Follows the Interface Segregation Principle (ISP) from SOLID.
"""
from abc import ABC, abstractmethod


class IPasswordHandler(ABC):
    """
    Interface for password handling services.
    
    All password handling implementations must adhere to this interface.
    This follows the Dependency Inversion Principle by allowing high-level modules
    to depend on this abstraction rather than concrete implementations.
    """
    
    @abstractmethod
    async def hash_password(self, password: str) -> str:
        """
        Hash a plaintext password.
        
        Args:
            password: The plaintext password to hash
            
        Returns:
            The hashed password as a string
        """
        pass
    
    @abstractmethod
    async def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify if a plaintext password matches a hashed password.
        
        Args:
            plain_password: The plaintext password to verify
            hashed_password: The hashed password to compare against
            
        Returns:
            True if the password matches, False otherwise
        """
        pass
    
    @abstractmethod
    async def generate_reset_token(self, user_id: str) -> str:
        """
        Generate a secure token for password reset operations.
        
        Args:
            user_id: The ID of the user requesting a password reset
            
        Returns:
            A secure token string
        """
        pass
    
    @abstractmethod
    async def verify_reset_token(self, token: str) -> str:
        """
        Verify a password reset token and extract the user ID.
        
        Args:
            token: The reset token to verify
            
        Returns:
            The user ID if the token is valid
            
        Raises:
            ValueError: If the token is invalid or expired
        """
        pass
    
    @abstractmethod
    async def password_meets_requirements(self, password: str) -> bool:
        """
        Check if a password meets security requirements.
        
        Args:
            password: The password to check
            
        Returns:
            True if the password meets requirements, False otherwise
        """
        pass