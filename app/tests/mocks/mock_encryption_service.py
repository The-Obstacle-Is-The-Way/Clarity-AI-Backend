"""
Mock implementation of encryption service for testing.

This module provides a deterministic mock encryption service that can be
used in tests without needing actual cryptographic dependencies.
"""

import base64
import json
import logging
from typing import Any, Dict, Optional, Union
import hashlib

from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService

logger = logging.getLogger(__name__)

class MockEncryptionService(BaseEncryptionService):
    """
    Mock encryption service for testing.
    
    This service implements all BaseEncryptionService methods with deterministic
    simple encoding/decoding that doesn't use actual cryptography.
    """
    
    def __init__(self, key: str = "mock_test_key", previous_key: Optional[str] = None):
        """Initialize the mock encryption service with deterministic keys."""
        self._key = key
        self._previous_key = previous_key
        self._version = "v1"  # Match real versioning pattern
        self._initialized = True
        
        # Add a mock cipher object with decrypt/encrypt methods to match BaseEncryptionService
        class MockCipher:
            def __init__(self, key):
                self.key = key
                
            def encrypt(self, data):
                # Simple "encryption" - XOR with key and add padding
                mock_key_bytes = self.key.encode('utf-8')
                mock_key_len = len(mock_key_bytes)
                
                result = bytearray(len(data))
                for i, b in enumerate(data):
                    result[i] = b ^ mock_key_bytes[i % mock_key_len]
                    
                return result
                
            def decrypt(self, data):
                # Simple "decryption" - same XOR operation as encryption
                mock_key_bytes = self.key.encode('utf-8')
                mock_key_len = len(mock_key_bytes)
                
                result = bytearray(len(data))
                for i, b in enumerate(data):
                    result[i] = b ^ mock_key_bytes[i % mock_key_len]
                    
                return bytes(result)
        
        # Create and assign the mock cipher
        self.cipher = MockCipher(key)
        
        logger.debug(f"MockEncryptionService initialized with key: {key[:3]}***")
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """
        Mock encrypt data with a deterministic algorithm.
        Returns the result as a versioned string.
        """
        if not isinstance(data, (str, bytes)):
            raise ValueError(f"Data must be string or bytes, got {type(data)}")
        
        # Convert to bytes if string
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Simple "encryption" for test purposes only - not secure
        # XOR with the key and encode with base64
        mock_key_bytes = self._key.encode('utf-8')
        mock_key_len = len(mock_key_bytes)
        
        result = bytearray(len(data_bytes))
        for i, b in enumerate(data_bytes):
            result[i] = b ^ mock_key_bytes[i % mock_key_len]
        
        # Encode with base64 for string representation
        encoded = base64.b64encode(result).decode('utf-8')
        
        # Return with version prefix (like real service)
        return f"{self._version}:{encoded}"
    
    def decrypt(self, encrypted_data: Union[str, bytes]) -> bytes:
        """
        Mock decrypt data that was encrypted with the mock encrypt method.
        Expects a versioned string as input.
        
        Returns:
            Decrypted data as bytes (to match BaseEncryptionService)
        """
        if encrypted_data is None:
            return None
            
        # Convert to string if bytes
        if isinstance(encrypted_data, bytes):
            encrypted_str = encrypted_data.decode('utf-8')
        else:
            encrypted_str = encrypted_data
        
        # Split version and data
        try:
            version, data = encrypted_str.split(':', 1)
        except ValueError:
            raise ValueError(f"Invalid encrypted data format: {encrypted_str}")
        
        # Check version
        if version != self._version:
            logger.warning(f"Version mismatch: {version} != {self._version}")
        
        # Decode base64
        try:
            decoded = base64.b64decode(data)
        except Exception as e:
            raise ValueError(f"Invalid base64 data: {e}")
        
        # Reverse the "encryption" - XOR again
        mock_key_bytes = self._key.encode('utf-8')
        mock_key_len = len(mock_key_bytes)
        
        result = bytearray(len(decoded))
        for i, b in enumerate(decoded):
            result[i] = b ^ mock_key_bytes[i % mock_key_len]
        
        # Return as bytes to match BaseEncryptionService (not as string)
        return bytes(result)
    
    def encrypt_dict(self, data: Dict[str, Any], encrypt_keys: Optional[list[str]] = None) -> Dict[str, Any]:
        """
        Mock encrypt specified fields in a dictionary.
        If encrypt_keys is None, encrypts all values.
        """
        if not data:
            return {}
            
        # Make a copy to avoid modifying original
        result = data.copy()
        
        # If no keys specified, encrypt all string values
        keys_to_encrypt = encrypt_keys or list(result.keys())
        
        for key in keys_to_encrypt:
            if key in result and result[key] is not None:
                # Handle nested dicts
                if isinstance(result[key], dict):
                    result[key] = self.encrypt_dict(result[key])
                # Handle lists - encrypt each item if it's a string or dict
                elif isinstance(result[key], list):
                    result[key] = [
                        self.encrypt_dict(item) if isinstance(item, dict)
                        else self.encrypt(json.dumps(item)) if not isinstance(item, (str, bytes))
                        else self.encrypt(item)
                        for item in result[key]
                    ]
                # Handle simple values - convert to string first if not already
                else:
                    value = result[key]
                    if not isinstance(value, (str, bytes)):
                        value = json.dumps(value)
                    result[key] = self.encrypt(value)
        
        return result
    
    def decrypt_dict(self, data: Dict[str, Any], decrypt_keys: Optional[list[str]] = None) -> Dict[str, Any]:
        """
        Mock decrypt specified fields in a dictionary.
        If decrypt_keys is None, decrypts all values that look encrypted.
        """
        if not data:
            return {}
            
        # Make a copy to avoid modifying original
        result = data.copy()
        
        # If no keys specified, try to decrypt all values that look encrypted
        keys_to_decrypt = decrypt_keys or list(result.keys())
        
        for key in keys_to_decrypt:
            if key in result and result[key] is not None:
                # Handle nested dicts
                if isinstance(result[key], dict):
                    result[key] = self.decrypt_dict(result[key])
                # Handle lists - decrypt each item if it looks encrypted
                elif isinstance(result[key], list):
                    result[key] = [
                        self.decrypt_dict(item) if isinstance(item, dict)
                        else self.decrypt(item) if isinstance(item, (str, bytes)) and self._looks_encrypted(item)
                        else item
                        for item in result[key]
                    ]
                # Handle simple values - decrypt if it looks encrypted
                elif isinstance(result[key], (str, bytes)) and self._looks_encrypted(result[key]):
                    try:
                        decrypted = self.decrypt(result[key])
                        # Try to parse as JSON if it looks like a serialized object
                        if decrypted.startswith('{') and decrypted.endswith('}'):
                            try:
                                result[key] = json.loads(decrypted)
                            except json.JSONDecodeError:
                                result[key] = decrypted
                        else:
                            result[key] = decrypted
                    except Exception as e:
                        logger.warning(f"Failed to decrypt {key}: {e}")
                        result[key] = result[key]  # Keep original
        
        return result
    
    def _looks_encrypted(self, value: Union[str, bytes]) -> bool:
        """Check if a value looks like it was encrypted by this service."""
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        return value.startswith(f"{self._version}:")
    
    def generate_hash(self, data: str) -> str:
        """Generate a deterministic hash for testing."""
        return hashlib.sha256(f"{data}{self._key}".encode()).hexdigest()
    
    def verify_hash(self, data: str, hash_value: str) -> bool:
        """Verify a hash generated by generate_hash."""
        return self.generate_hash(data) == hash_value
    
    def generate_hmac(self, data: str) -> str:
        """Generate a deterministic HMAC for testing."""
        return hashlib.sha256(f"{data}{self._key}".encode()).hexdigest()
    
    def verify_hmac(self, data: str, hmac_value: str) -> bool:
        """Verify an HMAC generated by generate_hmac."""
        return self.generate_hmac(data) == hmac_value
    
    def decrypt_string(self, value: Union[str, bytes, None]) -> Optional[str]:
        """
        Mock decrypt a string that was encrypted with encrypt_string.
        
        Args:
            value: Encrypted string or bytes
            
        Returns:
            Decrypted string
            
        Raises:
            ValueError: If decryption fails
        """
        if value is None:
            return None
            
        try:
            # Decrypt to bytes
            decrypted_bytes = self.decrypt(value)
            
            # Convert bytes to string - easier for mock as we know it's utf-8
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            logger.error(f"String decryption failed in mock: {str(e)}")
            raise ValueError(f"Mock string decryption failed: {str(e)}")
            
    def encrypt_string(self, value: str) -> str:
        """
        Mock encrypt a string.
        
        Args:
            value: String to encrypt
            
        Returns:
            Encrypted string
            
        Raises:
            ValueError: If encryption fails
        """
        if value is None:
            return None
            
        # Direct pass-through to encrypt
        return self.encrypt(value) 