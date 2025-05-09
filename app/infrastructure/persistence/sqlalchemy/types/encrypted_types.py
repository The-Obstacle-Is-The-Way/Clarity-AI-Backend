"""
SQLAlchemy TypeDecorators for Encrypted Data.

This module provides TypeDecorator implementations that automatically
encrypt data when writing to the database and decrypt it when reading,
using the application's configured encryption service.
"""

import logging
from sqlalchemy import types, Text
import json

# Import the core encryption/decryption functions
# from the encryption module which re-exports them properly
from app.infrastructure.security.encryption import encrypt_value, decrypt_value

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

class EncryptedText(EncryptedTypeBase):
    """SQLAlchemy TypeDecorator for automatically encrypting/decrypting large text fields."""
    
    @property
    def python_type(self):
        # The underlying Python type for Text is also str
        return str

class EncryptedJSON(EncryptedTypeBase):
    """SQLAlchemy TypeDecorator for automatically encrypting/decrypting JSON serializable objects."""

    @property
    def python_type(self):
        # Could be dict, list, etc. The base type decorator handles the actual SQL type.
        # For flexibility, we don't pin it to a specific collection type here.
        return object 

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        try:
            json_string = json.dumps(value)
            # logger.debug(f"EncryptedJSON process_bind_param: Serialized to JSON: '{json_string[:100]}...'")
            encrypted = super().process_bind_param(json_string, dialect)
            # logger.debug(f"EncryptedJSON process_bind_param: Encryption result: '{encrypted[:50] if encrypted else 'None'}...'")
            return encrypted
        except TypeError as e:
            logger.error(f"JSON serialization failed for value: {value}. Error: {e}", exc_info=True)
            raise ValueError("JSON serialization failed during bind parameter processing.") from e
        except Exception as e:
            logger.error(f"Encryption failed for JSON object: {e}", exc_info=True)
            raise ValueError("Encryption for JSON object failed during bind parameter processing.") from e

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            decrypted_string = super().process_result_value(value, dialect)
            if decrypted_string is None: # Superclass might return None on decryption failure
                # logger.debug("EncryptedJSON process_result_value: Decrypted string is None, returning None.")
                return None
            # logger.debug(f"EncryptedJSON process_result_value: Decrypted string: '{decrypted_string[:100]}...'")
            deserialized_json = json.loads(decrypted_string)
            # logger.debug(f"EncryptedJSON process_result_value: Deserialized JSON: type {type(deserialized_json)}")
            return deserialized_json
        except json.JSONDecodeError as e:
            logger.error(f"JSON deserialization failed for decrypted string: '{decrypted_string if 'decrypted_string' in locals() else value[:100]}...'. Error: {e}", exc_info=True)
            # Depending on policy, could return the raw decrypted string, None, or raise
            return None # Or raise ValueError("JSON deserialization failed.")
        except Exception as e:
            logger.error(f"Decryption or JSON deserialization failed: {e}", exc_info=True)
            return None # Or raise

__all__ = [
    "EncryptedString",
    "EncryptedText",
    "EncryptedJSON",
    # Add other encrypted types here when defined
]

logger.info("Encrypted SQLAlchemy type decorators defined.") 