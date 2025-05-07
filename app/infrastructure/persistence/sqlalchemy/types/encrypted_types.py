"""
SQLAlchemy TypeDecorators for Encrypted Data.

This module provides TypeDecorator implementations that automatically
encrypt data when writing to the database and decrypt it when reading,
using the application's configured encryption service.
"""

import logging
from sqlalchemy import types, Text

# Import the core encryption/decryption functions
# Assuming these handle the key loading internally via settings
from app.infrastructure.security.encryption.base_encryption_service import (
    encrypt_value, 
    decrypt_value
)

logger = logging.getLogger(__name__)

class EncryptedTypeBase(types.TypeDecorator):
    """Base class for encrypted types, storing data as Text."""
    # Store encrypted data as TEXT, suitable for base64 encoded ciphertext
    impl = Text 
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Encrypt the value before sending it to the database."""
        if value is None:
            # logger.debug("process_bind_param: value is None, returning None.")
            return None
        try:
            # Convert potential non-string simple types before encryption
            value_str = str(value) 
            # logger.debug(f"process_bind_param: Encrypting value: '{value_str[:50]}...'")
            encrypted = encrypt_value(value_str)
            # logger.debug(f"process_bind_param: Encryption result: '{encrypted[:50] if encrypted else 'None'}...'")
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed during bind processing: {e}", exc_info=True)
            # Depending on policy, either raise, return None, or return original value
            raise ValueError("Encryption failed during bind parameter processing.") from e

    def process_result_value(self, value, dialect):
        """Decrypt the value after retrieving it from the database."""
        if value is None:
            # logger.debug("process_result_value: value is None, returning None.")
            return None
        if not isinstance(value, str):
             logger.warning(f"process_result_value: Expected string from DB for decryption, got {type(value)}. Returning as is.")
             return value # Or attempt conversion/raise error
        try:
            # logger.debug(f"process_result_value: Decrypting value: '{value[:50]}...'")
            decrypted = decrypt_value(value)
            # logger.debug(f"process_result_value: Decryption result: '{decrypted[:50] if decrypted else 'None'}...'")
            return decrypted
        except Exception as e:
            logger.error(f"Decryption failed during result processing: {e}", exc_info=True)
            # Depending on policy, either raise, return None, or return original (encrypted) value
            # Returning None might be safer to avoid exposing encrypted data on failure
            return None 

    @property
    def python_type(self):
        """Specifies the Python type this decorator handles."""
        # This should be overridden by subclasses
        raise NotImplementedError


class EncryptedString(EncryptedTypeBase):
    """SQLAlchemy TypeDecorator for automatically encrypting/decrypting strings."""
    
    @property
    def python_type(self):
        return str

# TODO: Define EncryptedText (potentially inheriting from EncryptedString or EncryptedTypeBase)
# TODO: Define EncryptedDate (handle date/datetime objects, store encrypted ISO string)
# TODO: Define EncryptedJSON (handle dict/list, serialize to JSON, encrypt string)

__all__ = [
    "EncryptedString",
    # Add other encrypted types here when defined
]

logger.info("Encrypted SQLAlchemy type decorators defined.") 