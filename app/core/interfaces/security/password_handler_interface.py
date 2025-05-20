"""
Interface for Password Handler.

This module defines the interface for password handling services that manage
secure password operations such as hashing, verification, and validation
in compliance with HIPAA security requirements.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple


class IPasswordHandler(ABC):
    """
    Interface for password handling services.
    
    Implementations of this interface should handle secure password operations
    including hashing, verification, and validation in accordance with
    security best practices and HIPAA requirements.
    """
    
    @abstractmethod
    def hash_password(self, password: str) -> str:
        """
        Create a secure hash of a password.
        
        Args:
            password: The plain text password to hash
            
        Returns:
            A securely hashed password string
        """
        pass
    
    @abstractmethod
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify that a plain text password matches a hashed password.
        
        Args:
            plain_password: The plain text password to verify
            hashed_password: The hashed password to compare against
            
        Returns:
            True if the password matches, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_password_strength(self, password: str) -> Tuple[bool, Optional[List[str]]]:
        """
        Validate the strength of a password against security requirements.
        
        Args:
            password: The password to validate
            
        Returns:
            A tuple containing:
            - A boolean indicating if the password meets requirements
            - A list of validation failure messages (if any)
        """
        pass
    
    @abstractmethod
    def get_password_strength_score(self, password: str) -> Dict[str, any]:
        """
        Calculate a strength score for a password.
        
        Args:
            password: The password to evaluate
            
        Returns:
            A dictionary containing the strength score and analysis details
        """
        pass