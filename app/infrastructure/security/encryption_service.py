"""
Encryption service implementation.

This module implements the EncryptionServiceInterface to provide
HIPAA-compliant encryption for all PHI data in the system.
"""

import base64
import hashlib
import hmac
import os
import secrets
from typing import Any, Dict, Optional, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.interfaces.services.encryption_service_interface import EncryptionServiceInterface


class EncryptionService(EncryptionServiceInterface):
    """
    Implementation of the encryption service with HIPAA-compliant encryption.
    
    This service uses Fernet (symmetric encryption) with proper key management
    to ensure data is encrypted at rest and in transit. It follows the
    Single Responsibility Principle by focusing solely on encryption operations.
    """
    
    def __init__(self, master_key: Optional[bytes] = None):
        """
        Initialize the encryption service.
        
        Args:
            master_key: Optional master key for encryption/decryption
        """
        # Use provided key or generate a new one
        self._master_key = master_key or self._load_or_generate_master_key()
        self._fernet = Fernet(self._master_key)
    
    def encrypt(self, data: Union[str, bytes], context: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Encrypt data with optional context.
        
        This implementation uses Fernet symmetric encryption with
        a derived key if context is provided for additional security.
        
        Args:
            data: Data to encrypt, either as string or bytes
            context: Optional metadata context for encryption
            
        Returns:
            Encrypted data as bytes
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Use context-specific key if context provided
        if context:
            # Derive a specific key for this context
            context_key = self._derive_key_from_context(context)
            fernet = Fernet(context_key)
            return fernet.encrypt(data_bytes)
        
        # Use master key if no context
        return self._fernet.encrypt(data_bytes)
    
    def decrypt(self, encrypted_data: bytes, context: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Decrypt previously encrypted data with optional context.
        
        Args:
            encrypted_data: Data to decrypt
            context: Optional metadata context for decryption
            
        Returns:
            Decrypted data as bytes
        """
        try:
            # Use context-specific key if context provided
            if context:
                context_key = self._derive_key_from_context(context)
                fernet = Fernet(context_key)
                return fernet.decrypt(encrypted_data)
            
            # Use master key if no context
            return self._fernet.decrypt(encrypted_data)
        except Exception as e:
            # Security best practice: don't expose detailed error info
            raise ValueError("Decryption failed") from e
    
    def hash_sensitive_data(self, data: str) -> str:
        """
        Create a one-way hash of sensitive data for storage or comparison.
        
        Uses HMAC with SHA-256 for secure, keyed hashing to prevent
        rainbow table attacks.
        
        Args:
            data: Sensitive data to hash
            
        Returns:
            Secure hash as string
        """
        # Use HMAC with our master key for extra security
        h = hmac.new(self._master_key, data.encode('utf-8'), hashlib.sha256)
        return base64.b64encode(h.digest()).decode('utf-8')
    
    def generate_key(self) -> bytes:
        """
        Generate a new encryption key.
        
        Returns:
            New encryption key as bytes
        """
        return Fernet.generate_key()
    
    def _load_or_generate_master_key(self) -> bytes:
        """
        Load the master key from environment or generate a new one.
        
        Returns:
            Master encryption key
        """
        # In production, would load from secure key management system
        # For test collection, generate a random key
        env_key = os.environ.get("ENCRYPTION_MASTER_KEY")
        if env_key:
            try:
                return base64.b64decode(env_key)
            except Exception:
                # Fallback to generating new key
                pass
        
        return Fernet.generate_key()
    
    def _derive_key_from_context(self, context: Dict[str, Any]) -> bytes:
        """
        Derive a specific key from the master key and context.
        
        This allows context-specific encryption while maintaining
        a single master key.
        
        Args:
            context: Context to derive key from
            
        Returns:
            Derived key as bytes
        """
        # Create a deterministic salt from the context
        context_str = str(sorted(context.items()))
        salt = hashlib.sha256(context_str.encode('utf-8')).digest()
        
        # Use PBKDF2 to derive a key from the master key and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # High iteration count for security
        )
        
        # Derive and format key for Fernet
        key_bytes = kdf.derive(self._master_key)
        return base64.urlsafe_b64encode(key_bytes)