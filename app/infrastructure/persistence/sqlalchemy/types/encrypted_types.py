"""
SQLAlchemy TypeDecorators for Encrypted Data.

This module provides TypeDecorator implementations that automatically
encrypt data when writing to the database and decrypt it when reading,
using the application's configured encryption service.
"""

import logging
from sqlalchemy import types, Text
import json
from sqlalchemy.engine import Dialect
from typing import Any

# Import the core encryption/decryption functions
# from the encryption module which re-exports them properly
from app.infrastructure.security.encryption import encrypt_value, decrypt_value

logger = logging.getLogger(__name__)

class EncryptedTypeBase(types.TypeDecorator):
    """Base class for encrypted types, storing data as Text."""
    # Store encrypted data as TEXT, suitable for base64 encoded ciphertext
    impl = Text 
    cache_ok = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        """Encrypt the value before sending it to the database."""
        if value is None:
            # logger.debug("process_bind_param: value is None, returning None.")
            return None
        try:
            # Convert potential non-string simple types before encryption
            value_str = str(value) 
            # logger.debug(f"process_bind_param: Encrypting value: '{value_str[:50]}...'")
            from app.infrastructure.persistence.sqlalchemy.models.patient import encryption_service_instance as esi
            encrypted = esi.encrypt(value_str)
            # logger.debug(f"process_bind_param: Encryption result: '{encrypted[:50] if encrypted else 'None'}...'")
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed during bind processing: {e}", exc_info=True)
            # Depending on policy, either raise, return None, or return original value
            raise ValueError("Encryption failed during bind parameter processing.") from e

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:
        """Decrypt the value after retrieving it from the database."""
        if value is None:
            # logger.debug("process_result_value: value is None, returning None.")
            return None
        if not isinstance(value, str):
             logger.warning(f"process_result_value: Expected string from DB for decryption, got {type(value)}. Returning as is.")
             return value # Or attempt conversion/raise error
        try:
            # logger.debug(f"process_result_value: Decrypting value: '{value[:50]}...'")
            from app.infrastructure.persistence.sqlalchemy.models.patient import encryption_service_instance as esi
            decrypted = esi.decrypt(value)
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
        # Could be dict, list, etc., but often loaded as dict
        return dict # Or object, if various types are expected

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            # Consistently return None if the input value is None.
            # The encryption service should handle encrypting None if necessary,
            # or this None will be stored as NULL if the column is nullable.
            return None
        
        json_string = None
        try:
            # Priority 1: Pydantic BaseModel
            if hasattr(value, 'model_dump_json') and callable(value.model_dump_json):
                json_string = value.model_dump_json()
            # Priority 2: Objects with to_dict() method (e.g., custom dataclasses)
            elif hasattr(value, 'to_dict') and callable(value.to_dict):
                dict_val = value.to_dict()
                json_string = json.dumps(dict_val) 
            # Priority 3: Standard json.dumps for basic types (dict, list, str, int, float, bool, None)
            else:
                json_string = json.dumps(value)
        except TypeError as e:
            logger.error(f"EncryptedJSON: Failed to serialize value of type {type(value)}: {e}. Value: {str(value)[:200]}")
            # Re-raise as a ValueError to be caught by SQLAlchemy's error handling or higher up
            raise ValueError(f"JSON serialization failed for EncryptedJSON input type {type(value)}: {e}") from e
            
        # Ensure that json_string is not None before encryption if value was not None
        if json_string is None and value is not None:
            # This case should ideally not be reached if serialization succeeded or raised an error.
            # It implies a logic flaw above or an unexpected non-serializable type that didn't raise TypeError.
            logger.error(f"EncryptedJSON: json_string is None after serialization attempt for non-None value of type {type(value)}.")
            # Decide handling: encrypt a placeholder, raise, or return None (leading to NULL in DB)
            # Raising an error is safer to highlight the serialization issue.
            raise ValueError("EncryptedJSON: Serialization resulted in None for a non-None value.")

        # Access encryption service directly from patient model module
        from app.infrastructure.persistence.sqlalchemy.models.patient import encryption_service_instance as esi
        encrypted_data = esi.encrypt(json_string)
        return encrypted_data

    def process_result_value(self, value: str | None, dialect: Dialect) -> Any | None:
        if value is None:
            return None
        # Access encryption service directly from patient model module
        from app.infrastructure.persistence.sqlalchemy.models.patient import encryption_service_instance as esi
        try:
            decrypted_json_string = esi.decrypt(value)
            if decrypted_json_string is None: # Should not happen if encryption stores non-None for non-None
                return None
            return json.loads(decrypted_json_string)
        except json.JSONDecodeError as e:
            logger.error(f"EncryptedJSON: Failed to decode JSON after decryption: {e}. Value: {value[:100]}", exc_info=True)
            # Depending on requirements, either raise or return as is, or return None
            # Raising helps identify issues.
            raise ValueError("Failed to decode JSON from encrypted data.") from e
        except Exception as e:
            logger.error(f"EncryptedJSON: Decryption or JSON processing failed: {e}", exc_info=True)
            # Catch-all for other decryption/processing errors
            raise ValueError("Failed to process encrypted JSON data.") from e

__all__ = [
    "EncryptedString",
    "EncryptedText",
    "EncryptedJSON",
    "EncryptedTypeBase",
    # Add other encrypted types here when defined
]

logger.info("Encrypted SQLAlchemy type decorators defined.") 