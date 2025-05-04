"""
Encryption service interface definition.

This module defines the abstract interface for encryption services
following clean architecture principles with proper separation of concerns.
The encryption service ensures HIPAA compliance through data protection.
"""

from abc import ABC, abstractmethod
from typing import Any


class IEncryptionService(ABC):
    """
    Abstract interface for encryption services.
    
    This interface defines the contract for encryption operations,
    allowing for different implementations while maintaining a
    consistent interface throughout the application.
    """
    
    @abstractmethod
    def encrypt(self, data: str | bytes, context: dict[str, Any] | None = None) -> bytes:
        """
        Encrypt data with optional context.
        
        Args:
            data: Data to encrypt, either as string or bytes
            context: Optional metadata context for encryption
            
        Returns:
            Encrypted data as bytes
        """
        raise NotImplementedError
    
    @abstractmethod
    def decrypt(self, encrypted_data: bytes, context: dict[str, Any] | None = None) -> bytes:
        """
        Decrypt previously encrypted data with optional context.
        
        Args:
            encrypted_data: Data to decrypt
            context: Optional metadata context for decryption
            
        Returns:
            Decrypted data as bytes
        """
        raise NotImplementedError
    
    @abstractmethod
    def hash_sensitive_data(self, data: str) -> str:
        """
        Create a one-way hash of sensitive data for storage or comparison.
        
        Args:
            data: Sensitive data to hash
            
        Returns:
            Secure hash as string
        """
        raise NotImplementedError
    
    @abstractmethod
    def generate_key(self) -> bytes:
        """
        Generate a new encryption key.
        
        Returns:
            New encryption key as bytes
        """
        raise NotImplementedError