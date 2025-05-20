"""
Interface for Password Handler.

This module defines the interface for password handling services that manage
secure password operations such as hashing, verification, and validation
in compliance with HIPAA security requirements.
"""

from abc import ABC, abstractmethod
from typing import Any


class IPasswordHandler(ABC):
    """
    Interface for password handling services.
    
    Implementations of this interface should handle secure password operations
    including hashing, verification, and validation in accordance with
    security best practices and HIPAA requirements.
    """
    
    @abstractmethod
    def get_password_hash(self, password: str) -> str:
        """
        Hashes a plain text password.

        Args:
            password: The plain text password.

        Returns:
            The hashed password.
        """
        pass
    
    @abstractmethod
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verifies a plain text password against a hashed password.

        Args:
            plain_password: The plain text password.
            hashed_password: The hashed password to compare against.

        Returns:
            True if the password matches, False otherwise.
        """
        pass
    
    @abstractmethod
    def password_needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if a password hash needs to be upgraded.

        Args:
            hashed_password: Currently stored password hash

        Returns:
            True if rehashing is recommended, False otherwise
        """
        pass
    
    @abstractmethod
    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure random password.

        Args:
            length: Length of password to generate (default: 16)

        Returns:
            Secure random password string
        """
        pass
    
    @abstractmethod
    def hash_password(self, password: str) -> str:
        """
        Alias for get_password_hash (retained for backwards-compat).
        
        Args:
            password: The plain text password to hash
            
        Returns:
            A securely hashed password string
        """
        pass
    
    @abstractmethod
    def check_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Alias for verify_password (retained for backwards-compat).
        
        Args:
            plain_password: The plain text password to verify
            hashed_password: The hashed password to compare against
            
        Returns:
            True if the password matches, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_password_strength(self, password: str) -> tuple[bool, str | None]:
        """
        Validate password strength against HIPAA-compliant security requirements.

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        pass
    
    @abstractmethod
    def validate_password_complexity(self, password: str) -> tuple[bool, str]:
        """
        Validate if a password meets complexity requirements.

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        pass
    
    @abstractmethod
    def is_common_password(self, password: str) -> bool:
        """
        Check if a password has been compromised in known breaches.

        Args:
            password: Password to check

        Returns:
            True if the password appears to be breached, False otherwise
        """
        pass
    
    @abstractmethod
    def suggest_password_improvement(self, password: str) -> str:
        """
        Provide improvement suggestions for a password.

        Args:
            password: Password to analyze

        Returns:
            Suggestion message
        """
        pass
        
    @abstractmethod
    def get_password_strength_feedback(self, password: str) -> dict[str, Any]:
        """
        Get detailed feedback on password strength.

        Args:
            password: The password to analyze

        Returns:
            dict[str, Any]: Detailed feedback containing strength score,
                            suggestions for improvement, and other metrics
        """
        pass