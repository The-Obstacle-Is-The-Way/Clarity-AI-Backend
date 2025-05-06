"""
Password Handler Interface.

This module defines the interface for password handling, including hashing, verification,
and strength validation, following clean architecture principles.
"""

from abc import ABC, abstractmethod
from typing import Dict, Tuple, Optional


class IPasswordHandler(ABC):
    """Interface for password handling operations.
    
    This interface defines the contract that any password handler implementation
    must follow. It provides methods for password hashing, verification, and 
    strength validation to ensure security best practices across the application.
    """
    
    @abstractmethod
    def hash_password(self, password: str) -> str:
        """Hash a password securely.
        
        Args:
            password: The plain text password to hash
            
        Returns:
            str: The securely hashed password
        """
        pass
    
    @abstractmethod
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.
        
        Args:
            plain_password: The plain text password to verify
            hashed_password: The hashed password to check against
            
        Returns:
            bool: True if the password matches, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate the strength of a password.
        
        Args:
            password: The plain text password to validate
            
        Returns:
            Tuple[bool, str]: A tuple containing:
                - A boolean indicating if the password meets strength requirements
                - A message describing the validation result or any failures
        """
        pass
    
    @abstractmethod
    def get_password_strength_feedback(self, password: str) -> Dict[str, any]:
        """Get detailed feedback on password strength.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dict[str, any]: Detailed feedback containing strength score, 
                            suggestions for improvement, and other metrics
        """
        pass
    
    @abstractmethod
    def is_common_password(self, password: str) -> bool:
        """Check if a password is in a list of commonly used/breached passwords.
        
        Args:
            password: The password to check
            
        Returns:
            bool: True if the password is common/breached, False otherwise
        """
        pass
    
    @abstractmethod
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a cryptographically secure random password.
        
        Args:
            length: The desired length of the password (default: 16)
            
        Returns:
            str: A secure random password
        """
        pass
