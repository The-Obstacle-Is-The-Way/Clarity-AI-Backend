"""
Encryption components for the Novamind Digital Twin Backend.

This module provides quantum-resistant encryption services for securing sensitive data,
including field-level encryption, key rotation, and HIPAA-compliant data protection.
"""

import base64
import json
import os
import logging
from typing import Dict, Any, Union

# Core encryption service
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService,
    encrypt_value,
    decrypt_value,
    get_encryption_key
)

# Field-level encryption utilities
from app.infrastructure.security.encryption.field_encryptor import (
    FieldEncryptor
)

# Configure logger
logger = logging.getLogger(__name__)

# PHI specific encryption functions
def encrypt_phi(data: Union[Dict[str, Any], str]) -> Union[Dict[str, Any], str]:
    """Encrypt PHI data with HIPAA-compliant encryption.
    
    Args:
        data: The data to encrypt (dictionary or string)
        
    Returns:
        Encrypted data in the same format as input
    """
    if isinstance(data, dict):
        # Create a BaseEncryptionService instance for encrypting the dictionary
        encryption_service = BaseEncryptionService()
        return encryption_service.encrypt_dict(data)
    else:
        # For simple string values, use the encrypt_value function
        return encrypt_value(str(data))

def decrypt_phi(encrypted_data: Union[Dict[str, Any], str]) -> Union[Dict[str, Any], str]:
    """Decrypt PHI data that was encrypted with encrypt_phi.
    
    Args:
        encrypted_data: The encrypted data to decrypt
        
    Returns:
        Decrypted data in the same format as input
    """
    if isinstance(encrypted_data, dict):
        # Create a BaseEncryptionService instance for decrypting the dictionary
        encryption_service = BaseEncryptionService()
        return encryption_service.decrypt_dict(encrypted_data)
    else:
        # For simple string values, use the decrypt_value function
        return decrypt_value(encrypted_data)

def encrypt_field(value: str) -> str:
    """Encrypt a single field with HIPAA-compliant encryption.
    
    Args:
        value: The value to encrypt
        
    Returns:
        Encrypted value as string
    """
    return encrypt_value(value)

def decrypt_field(encrypted_value: str) -> str:
    """Decrypt a field that was encrypted with encrypt_field.
    
    Args:
        encrypted_value: The encrypted value to decrypt
        
    Returns:
        Decrypted value
    """
    return decrypt_value(encrypted_value)

def generate_phi_key() -> str:
    """Generate a cryptographically secure key for PHI encryption.
    
    Returns:
        A base64-encoded 32-byte key suitable for Fernet encryption
    """
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    return key

# Set default exports to maintain clean imports across the codebase
__all__ = [
    'BaseEncryptionService',
    'encrypt_value',
    'decrypt_value',
    'get_encryption_key',
    'FieldEncryptor',
    'encrypt_phi',
    'decrypt_phi',
    'encrypt_field',
    'decrypt_field',
    'generate_phi_key'
]

# Potentially import from encryption_service if needed elsewhere
# from app.infrastructure.security.encryption.encryption_service import EncryptionService
# from app.infrastructure.security.encryption.encryption import (
#     EncryptionHandler, 
#     KeyRotationManager, 
#     AESEncryption
# ) 