"""
SQLAlchemy TypeDecorators for Encrypted Data.

This module provides TypeDecorator implementations that automatically
encrypt data when writing to the database and decrypt it when reading,
using the application's configured encryption service.
"""

import logging
from sqlalchemy import types, Text
import json
import base64
from sqlalchemy.engine import Dialect
from typing import Any

# Import the shared instance from the encryption module
from app.infrastructure.security.encryption import encryption_service_instance

logger = logging.getLogger(__name__)

class EncryptedTypeBase(types.TypeDecorator):
    """Base class for encrypted types, storing data as Text."""
    # Store encrypted data as TEXT, suitable for base64 encoded ciphertext
    impl = Text 
    cache_ok = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._constructor_args = args
        self._constructor_kwargs = kwargs
        self.encryption_service = encryption_service_instance

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        try:
            value_str = str(value) 
            # self.encryption_service is EncryptionService, its .encrypt() returns bytes.
            encrypted_bytes = self.encryption_service.encrypt(value_str) 
            
            if encrypted_bytes is None:
                logger.warning("EncryptionService.encrypt returned None for a non-None value.")
                return None # Or handle as an error

            # Create the version-prefixed, base64 encoded string for DB storage
            # VERSION_PREFIX should be accessible from self.encryption_service (inherited from BaseEncryptionService)
            prefixed_encrypted_string = f"{self.encryption_service.VERSION_PREFIX}{base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')}"
            return prefixed_encrypted_string

        except Exception as e:
            logger.error(f"Encryption failed during bind processing: {e}", exc_info=True)
            raise ValueError("Encryption failed during bind parameter processing.") from e

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:
        if value is None:
            return None

        str_value_from_db = None
        if isinstance(value, bytes): 
            try:
                str_value_from_db = value.decode('utf-8')
            except UnicodeDecodeError as e:
                raise ValueError(f"Invalid UTF-8 bytes in encrypted column: {e}") from e
        elif isinstance(value, str):
            str_value_from_db = value
        else:
            try:
                str_value_from_db = str(value)
            except Exception as e:
                raise TypeError(f"Cannot process unexpected input type {type(value)} in encrypted column: {e}") from e

        if str_value_from_db is None: 
             raise ValueError("Value from DB became None unexpectedly during processing.")

        try:
            # self.encryption_service is an EncryptionService instance.
            # Its .decrypt() method expects raw encrypted bytes (no prefix, no base64).

            if not str_value_from_db.startswith(self.encryption_service.VERSION_PREFIX):
                logger.error(f"Encrypted data from DB is missing version prefix '{self.encryption_service.VERSION_PREFIX}'. Value: {repr(str_value_from_db)}")
                raise ValueError("Encrypted data from DB is missing version prefix.")

            payload_b64 = str_value_from_db[len(self.encryption_service.VERSION_PREFIX):]
            
            try:
                raw_encrypted_bytes_payload = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
            except base64.binascii.Error as b64e:
                logger.error(f"Base64 decode error for payload: {payload_b64}. Error: {b64e}")
                raise ValueError("Invalid Base64 payload in encrypted data.") from b64e

            # Now pass the raw encrypted bytes to EncryptionService.decrypt
            decrypted_bytes = self.encryption_service.decrypt(raw_encrypted_bytes_payload)

            if decrypted_bytes is None:
                logger.warning(f"EncryptionService.decrypt returned None. Original encrypted value from DB: {repr(str_value_from_db)}")
                return None

            try:
                decrypted_final_str = decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError as ude:
                logger.error(f"UnicodeDecodeError after decryption. Bytes: {repr(decrypted_bytes)}. Error: {ude}")
                raise ValueError("Failed to decode decrypted bytes to UTF-8 string.") from ude
            
            return decrypted_final_str
        except ValueError as ve: 
            logger.error(f"ValueError during decryption process in EncryptedTypeBase: {ve}", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"Unexpected error during decryption process in EncryptedTypeBase: {e}, value from DB: {repr(str_value_from_db)}", exc_info=True)
            raise ValueError(f"Decryption process failed: {e}") from e

    @property
    def python_type(self):
        """Specifies the Python type this decorator handles."""
        # This should be overridden by subclasses
        raise NotImplementedError

    def copy(self, **kw):
        return self.__class__(*self._constructor_args, **self._constructor_kwargs)


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
        return dict # Or object, if various types are expected

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None # Let superclass handle None if it has specific logic, though it also returns None.
        
        json_string = None
        try:
            # Priority 1: Pydantic BaseModel V2+
            if hasattr(value, 'model_dump_json') and callable(value.model_dump_json):
                json_string = value.model_dump_json()
            # Priority for Pydantic BaseModel V1 (or similar .dict() method)
            elif hasattr(value, 'dict') and callable(value.dict):
                # Ensure it's not a standard dict's .dict method if that even exists
                # This check is a bit heuristic; ideally, rely on specific types.
                if not isinstance(value, dict) or 'model_dump' in dir(value): # Check if it might be Pydantic like
                    dict_val = value.dict() 
                    json_string = json.dumps(dict_val)
                else:
                    json_string = json.dumps(value) # Standard dict
            # Priority 2: Objects with to_dict() method (e.g., custom dataclasses)
            elif hasattr(value, 'to_dict') and callable(value.to_dict):
                dict_val = value.to_dict()
                json_string = json.dumps(dict_val) 
            # Priority 3: Standard json.dumps for basic types (dict, list, str, int, float, bool, None)
            else:
                json_string = json.dumps(value)
        except TypeError as e:
            logger.error(f"EncryptedJSON: Failed to serialize value of type {type(value)}: {e}. Value (repr): {repr(value)[:200]}")
            raise ValueError(f"JSON serialization failed for EncryptedJSON input type {type(value)}: {e}") from e
            
        if json_string is None and value is not None: # Should not happen if serialization worked or raised
            logger.error(f"EncryptedJSON: json_string is None after serialization attempt for non-None value of type {type(value)}.")
            raise ValueError("EncryptedJSON: Serialization resulted in None for a non-None value that should have been serialized.")

        # Delegate the encryption of the JSON string to the parent class's method
        return super().process_bind_param(json_string, dialect)

    def process_result_value(self, value: str | None, dialect: Dialect) -> Any | None:
        # `value` is the raw (potentially prefixed and base64 encoded) string from the DB.
        # Let the parent class handle decryption of this raw string to a plain JSON string.
        decrypted_json_string = super().process_result_value(value, dialect)

        if decrypted_json_string is None:
            return None
        
        try:
            # Now, parse the decrypted plain JSON string into a Python object (dict, list, etc.)
            return json.loads(decrypted_json_string)
        except json.JSONDecodeError as e:
            logger.error(f"EncryptedJSON: Failed to decode JSON from decrypted string: {e}. Decrypted string (repr): {repr(decrypted_json_string)}", exc_info=True)
            # It's important to know if the decrypted string was empty or malformed
            if not decrypted_json_string.strip():
                logger.error("EncryptedJSON: Decrypted string was empty or whitespace.")
            raise ValueError(f"Failed to decode JSON from decrypted data. Content (first 100 chars): '{decrypted_json_string[:100]}'") from e
        except Exception as e: # Catch any other error during json.loads
            logger.error(f"EncryptedJSON: Error processing decrypted JSON string: {e}. Decrypted string (repr): {repr(decrypted_json_string)}", exc_info=True)
            raise ValueError("Failed to process decrypted JSON data after decryption.") from e

__all__ = [
    "EncryptedString",
    "EncryptedText",
    "EncryptedJSON",
    "EncryptedTypeBase",
    # Add other encrypted types here when defined
]

logger.info("Encrypted SQLAlchemy type decorators defined.") 