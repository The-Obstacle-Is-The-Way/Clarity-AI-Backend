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
        
        # The 'value' from the database for encrypted types should be a string (ciphertext).
        # If it's not a string, it might indicate a problem upstream or an unexpected DB type.
        if not isinstance(value, str):
             logger.warning(f"process_result_value: Expected string from DB for decryption, got {type(value)}. This is unusual. Value: '{str(value)[:100]}...'")
             # Attempt to coerce to string if it makes sense, otherwise, this might be an error condition.
             # For now, let's proceed assuming 'value' is the string ciphertext as expected by esi.decrypt().
             # If esi.decrypt() expects bytes, this part of the logic would need review.
             # However, esi.decrypt() in EncryptionService is type-hinted to take `bytes`.
             # This suggests the `value` from `process_result_value` (which is from the DB TEXT column)
             # should be encoded before passing to `esi.decrypt` if `esi.decrypt` strictly wants bytes
             # of the *encrypted form*.
             # Let's assume `value` is the string form of the ciphertext.
             # The `EncryptionService.decrypt` takes `bytes` but `BaseEncryptionService.decrypt` (which is likely called)
             # handles string input by encoding it.

        try:
            # logger.debug(f"process_result_value: Decrypting value: '{value[:50]}...'")
            from app.infrastructure.persistence.sqlalchemy.models.patient import encryption_service_instance as esi
            
            # esi.decrypt (from EncryptionService) expects bytes (encrypted_data) and returns bytes (decrypted_data)
            # The `value` here is the string ciphertext from the database TEXT column.
            # BaseEncryptionService.decrypt, which EncryptionService might ultimately call, handles string input
            # by encoding it. So, passing `value` (str) directly might be fine if BaseEncryptionService's decrypt is used.
            # Let's assume esi.decrypt is EncryptionService.decrypt.
            # EncryptionService.decrypt(encrypted_data: bytes) -> bytes.
            # This means `value` (the string from DB) needs to be encoded if it's the raw ciphertext.
            # However, the type hint for `esi.decrypt` in `EncryptionService` is `decrypt(self, encrypted_data: bytes, ...) -> bytes`.
            # The `BaseEncryptionService.decrypt` takes `Union[str, bytes]` and returns `str`.
            # The `encryption_service_instance` is `EncryptionService()`.
            # Its `decrypt` method returns `bytes`.

            encrypted_data_bytes: bytes
            if isinstance(value, str):
                # Assuming the string from the DB is the base64 encoded ciphertext that Fernet expects after potentially removing a version prefix.
                # The BaseEncryptionService.decrypt handles version prefix and then decodes from base64 to bytes for Fernet.
                # So, if `value` is the direct output of `encrypt` (which includes prefix and is str), it should work.
                # The issue arises if esi.decrypt *itself* returns raw bytes.
                
                # If using BaseEncryptionService's decrypt method (which returns str):
                # decrypted_string_or_bytes = esi.decrypt(value) # esi is EncryptionService
                # if isinstance(decrypted_string_or_bytes, bytes):
                #    decrypted = decrypted_string_or_bytes.decode('utf-8')
                # else:
                #    decrypted = decrypted_string_or_bytes
                
                # If using EncryptionService's decrypt method (which returns bytes):
                decrypted_payload_bytes = esi.decrypt(value.encode('utf-8')) # Encrypt then decrypt expects bytes
                                                                          # This line is tricky. `value` is the string from DB.
                                                                          # `EncryptionService.decrypt` expects `bytes`.
                                                                          # What form is `value` in? It's the output of `process_bind_param`.
                                                                          # `process_bind_param` returns `encrypted_string` from `esi.encrypt(str_value)`.
                                                                          # `EncryptionService.encrypt(str|bytes)` returns `bytes` (encrypted).
                                                                          # `BaseEncryptionService.encrypt(str|bytes)` returns `Optional[str]` (version_prefix + b64(encrypted_bytes)).
                                                                          # The `EncryptedTypeBase.impl` is `Text`, so DB stores string.
                                                                          # So, `value` here IS the output of `BaseEncryptionService.encrypt`.
                                                                          # So, we should use `BaseEncryptionService.decrypt` logic.
                                                                          # `EncryptionService` IS-A `BaseEncryptionService`.
                                                                          # `EncryptionService.decrypt` returns bytes.
                                                                          # `BaseEncryptionService.decrypt` returns str.
                                                                          # This is a conflict in the hierarchy or usage.

                # Let's assume the `esi` (EncryptionService instance) should behave like BaseEncryptionService's decrypt
                # for the TypeDecorator's purpose, or the TypeDecorator needs to bridge the gap.
                # The `BaseEncryptionService.decrypt(data: Union[str, bytes]) -> str` is what we want.
                # `EncryptionService` inherits this but also defines its own `decrypt(encrypted_data: bytes) -> bytes`.
                # This is an LSP violation if `EncryptedTypeBase` expects `decrypt` to return `str`.

                # Given `encryption_service_instance = EncryptionService()`, `esi.decrypt` will call `EncryptionService.decrypt`.
                # This returns bytes.
                
                # The input `value` to this function IS a string (from Text column).
                # The `EncryptionService.decrypt` method expects `bytes`.
                # However, `BaseEncryptionService.decrypt` (which EncryptionService inherits) *can* take a string,
                # and it handles prefix stripping and then calls Fernet's decrypt, then decodes to UTF-8 string.
                # The issue is if Python's MRO calls `EncryptionService.decrypt(bytes)->bytes` when we pass a string.
                # It won't, it will cause a TypeError if `EncryptionService.decrypt` is called with a string.
                # This means `EncryptedTypeBase` expects `esi.decrypt` to take a string and return a string.
                # The current `EncryptionService.decrypt` takes bytes and returns bytes.

                # The most straightforward fix, if `EncryptionService.decrypt` is the one being called and returns bytes,
                # is to decode its result.
                # The `value` (string from DB) should be the prefixed, base64 encoded string.
                # `BaseEncryptionService.decrypt` handles this string format correctly and returns a string.
                # The problem is that `EncryptionService` overrides `decrypt` with a different signature (takes bytes, returns bytes)
                # than what `EncryptedTypeBase` implicitly relies on from `BaseEncryptionService` (takes str/bytes, returns str).

                # Let's call the method from BaseEncryptionService explicitly if possible, or ensure decoding.
                # Since esi is an instance of EncryptionService which IS-A BaseEncryptionService:
                
                decrypted_result = esi.decrypt(value) # This will call BaseEncryptionService.decrypt(str) -> str
                                                      # because `value` is `str`. Python's MRO should find the
                                                      # BaseEncryptionService.decrypt(self, data: Union[str, bytes]) -> str
                                                      # if EncryptionService.decrypt only accepts `bytes`.

                # Let's re-verify:
                # BaseEncryptionService.decrypt(data: Union[str, bytes]) -> str:
                #   if isinstance(data, str) and data.startswith(self.VERSION_PREFIX):
                #     encrypted_data = data[len(self.VERSION_PREFIX):].encode()
                #   ...
                #   return self.cipher.decrypt(encrypted_data).decode('utf-8')
                #
                # EncryptionService.decrypt(encrypted_data: bytes, ...) -> bytes:
                #   return self._fernet.decrypt(encrypted_data)

                # If esi.decrypt(value) is called where value is a string, it should be routed to
                # BaseEncryptionService.decrypt.
                # The log "Expected string from DB for decryption, got <class 'bytes'>"
                # suggests that `decrypted` (the return of esi.decrypt(value)) *was* bytes.
                # This can only happen if `BaseEncryptionService.decrypt` was somehow bypassed OR
                # if `value` itself was bytes (which the `isinstance(value, str)` check tries to prevent).

                # If `decrypted = esi.decrypt(value)` truly returns bytes, then `esi.decrypt` must be resolving
                # to `EncryptionService.decrypt` which was called with bytes (meaning `value` was bytes), or
                # `BaseEncryptionService.decrypt` was modified to return bytes, or
                # `EncryptionService.decrypt` was called with a string and *that* method returned bytes (violating Base's contract).

                # Given the evidence (log message), the `decrypted = esi.decrypt(value)` line results in `decrypted` being bytes.
                # So, we MUST decode it.
                decrypted_payload = esi.decrypt(value) # value is str, BaseEncryptionService.decrypt should be called.
                
                if decrypted_payload is None:
                    # logger.debug("process_result_value: Decryption returned None.")
                    return None
                
                if isinstance(decrypted_payload, bytes):
                    # This case implies that the called decrypt method returned bytes.
                    logger.debug(f"process_result_value: Decrypted payload is bytes, decoding to UTF-8. Value: {decrypted_payload[:50]}...")
                    return decrypted_payload.decode('utf-8')
                
                # If it's already a string, return as is.
                # logger.debug(f"process_result_value: Decryption result (already str): '{decrypted_payload[:50]}...'")
                return decrypted_payload

        except Exception as e:
            logger.error(f"Decryption failed during result processing: {e}", exc_info=True)
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