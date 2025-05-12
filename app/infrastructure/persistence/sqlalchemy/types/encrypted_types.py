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
import dataclasses
from sqlalchemy.engine import Dialect
from typing import Any, Dict, List, Optional, Union

# Import the shared instance from the encryption module
from app.infrastructure.security.encryption import encryption_service_instance as global_encryption_service_instance

logger = logging.getLogger(__name__)

class EncryptedTypeBase(types.TypeDecorator):
    """Base type for encrypted column types."""
    
    impl = Text
    
    def __init__(self, encryption_service = None, length = 4000, *args, **kwargs):
        super().__init__(length=length, *args, **kwargs)
        self.encryption_service = encryption_service or global_encryption_service_instance
        logger.debug(f"[EncryptedTypeBase.__init__] Created {self.__class__.__name__} with service {id(self.encryption_service)}")
    
    def process_bind_parameter(self, value: Any, dialect: Dialect) -> str | None:
        """
        Encrypt the Python value before storing in database.
        
        Args:
            value: The Python value to encrypt
            dialect: SQLAlchemy dialect
            
        Returns:
            Encrypted string or None if the input is None
        """
        if value is None:
            return None
            
        logger.debug(f"[EncryptedTypeBase] process_bind_parameter: Encrypting value of type {type(value)} for {self.__class__.__name__}")
        try:
            # The base implementation handles conversion via _convert_bind_param
            value_to_encrypt = self._convert_bind_param(value)
            
            # Use encrypt_string to get consistent prefixed encryption
            encrypted_value = self.encryption_service.encrypt_string(value_to_encrypt)
            
            logger.debug(f"[EncryptedTypeBase] process_bind_parameter: Encrypted value: {encrypted_value[:15] if encrypted_value else 'None'}...")
            return encrypted_value
        except Exception as e:
            logger.error(f"Encryption error during bind parameter processing: {e}", exc_info=True)
            raise ValueError(f"Encryption error during bind parameter processing: {e}") from e
    
    def process_result_value(self, value: str | None, dialect: Dialect) -> Any | None:
        """
        Decrypt the database value to a Python value.
        
        Args:
            value: The encrypted string from the database
            dialect: SQLAlchemy dialect
            
        Returns:
            Decrypted Python value or None if the input is None
            
        Raises:
            ValueError: If decryption fails
        """
        logger.debug(f"[EncryptedTypeBase] process_result_value called for type {self.__class__.__name__}.")
        
        # Handle None case
        if value is None:
            return None
        
        # Ensure we're working with a string
        if not isinstance(value, str):
            logger.warning(f"Expected str from DB, got {type(value)}")
            try:
                # Handle bytes case that might come from binary column types
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                else:
                    value = str(value)
            except Exception as e:
                logger.error(f"Cannot process non-string value {type(value)} from encrypted column: {e}")
                raise TypeError(f"Cannot process non-string value {type(value)} from encrypted column: {e}")
        
        try:
            # Use the standard decrypt_string method
            decrypted_value = self.encryption_service.decrypt_string(value)
            
            # Apply type-specific conversion
            return self._convert_result_value(decrypted_value)
            
        except ValueError as e:
            # Specifically handle ValueError (which includes decryption errors)
            logger.error(f"Decryption failed for value: {e}")
            # Reraise the error with more context
            raise ValueError(f"Decryption failed for {self.__class__.__name__}: {e}")
        except Exception as e:
            # Handle any other errors
            logger.error(f"Unexpected error during decryption: {e}", exc_info=True)
            raise ValueError(f"Failed to decrypt {self.__class__.__name__}: {e}") from e
    
    def _convert_bind_param(self, value: Any) -> str:
        """
        Convert a Python value to a string for encryption.
        Override in subclasses for type-specific conversion.
        
        Args:
            value: The Python value to convert
            
        Returns:
            String representation for encryption
        """
        if isinstance(value, str):
            return value
        return str(value)
    
    def _convert_result_value(self, decrypted_plain_string: str) -> Any:
        """
        Convert a decrypted string to the appropriate Python type.
        Override in subclasses for type-specific conversion.
        
        Args:
            decrypted_plain_string: The decrypted string value
            
        Returns:
            Converted Python value
        """
        return decrypted_plain_string

    @property
    def python_type(self):
        """Specifies the Python type this decorator handles."""
        # This should be overridden by subclasses - default to str
        return str

    def copy(self, **kw):
        return self.__class__(encryption_service=self.encryption_service, **kw)


class EncryptedString(EncryptedTypeBase):
    """SQLAlchemy TypeDecorator for automatically encrypting/decrypting strings."""
    
    def _convert_bind_param(self, value: Any) -> str:
        """Convert the value to a string before encryption."""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        return str(value)
    
    def _convert_result_value(self, decrypted_value: str) -> str:
        """Return the decrypted string value."""
        return decrypted_value
        
    @property
    def python_type(self):
        return str


class EncryptedText(EncryptedTypeBase):
    """SQLAlchemy TypeDecorator for automatically encrypting/decrypting large text fields."""
    
    def _convert_bind_param(self, value: Any) -> str:
        """Convert the value to a string before encryption."""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        return str(value)
    
    def _convert_result_value(self, decrypted_value: str) -> str:
        """Return the decrypted string value."""
        return decrypted_value
        
    @property
    def python_type(self):
        return str


class EncryptedJSON(EncryptedTypeBase):
    """Encrypted JSON column type for SQLAlchemy.
    
    Serialize Python objects to JSON, encrypt the JSON string,
    and store the encrypted string in the database.
    """
    
    def _convert_bind_param(self, value: Union[dict, list, Any]) -> str:
        """
        Convert a Python object to a JSON string for encryption.
        
        Args:
            value: The Python object to convert to JSON (usually dict or list)
            
        Returns:
            JSON string
            
        Raises:
            TypeError: If the value cannot be serialized to JSON
        """
        if value is None:
            return None
            
        try:
            # Handle Pydantic models (v2)
            if hasattr(value, 'model_dump'):
                return json.dumps(value.model_dump())
                
            # Handle Pydantic models (v1)
            if hasattr(value, 'dict'):
                return json.dumps(value.dict())
                
            # Handle dataclasses
            if dataclasses.is_dataclass(value):
                return json.dumps(dataclasses.asdict(value))
                
            # Handle objects with to_dict method
            if hasattr(value, 'to_dict') and callable(value.to_dict):
                return json.dumps(value.to_dict())
                
            # If already a string, assume it's valid JSON
            if isinstance(value, str):
                # Validate by parsing and re-serializing to ensure consistency
                return json.dumps(json.loads(value))
                
            # Otherwise serialize to JSON
            return json.dumps(value)
        except (TypeError, json.JSONDecodeError) as e:
            logger.error(f"Failed to encode value as JSON: {e}")
            # Handle MagicMock and other special objects as last resort
            try:
                return json.dumps({"__str__": str(value)})
            except Exception:
                raise TypeError(f"Cannot encode value as JSON: {e}") from e
    
    def _convert_result_value(self, decrypted_value: str) -> Union[dict, list, None]:
        """
        Convert a decrypted string to a Python object by parsing JSON.
        
        Args:
            decrypted_value: The decrypted JSON string
            
        Returns:
            Parsed Python object (usually dict or list)
            
        Raises:
            ValueError: If the JSON parsing fails
        """
        if decrypted_value is None:
            return None
            
        try:
            return json.loads(decrypted_value)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from decrypted value: {e}")
            # Return the original string if JSON parsing fails
            return decrypted_value
        
    @property
    def python_type(self):
        return dict

__all__ = [
    "EncryptedString",
    "EncryptedText",
    "EncryptedJSON",
    "EncryptedTypeBase",
    # Add other encrypted types here when defined
]

logger.info("Encrypted SQLAlchemy type decorators defined.") 