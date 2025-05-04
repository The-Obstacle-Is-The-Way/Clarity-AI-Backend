"""
Field-level encryption for HIPAA-compliant PHI protection.

This module provides surgical field-level encryption for sensitive patient data
following HIPAA requirements while maintaining clean architectural principles.
"""

import copy
import logging
from typing import Any

# Import our enhanced BaseEncryptionService
from .base_encryption_service import BaseEncryptionService

# Configure logger
logger = logging.getLogger(__name__)


class FieldEncryptor:
    """HIPAA-compliant field-level encryption for PHI data.
    
    Implements selective encryption/decryption of sensitive fields within complex 
    nested data structures (dictionaries and lists) using dot notation paths.
    """
    
    def __init__(self, encryption_service: BaseEncryptionService):
        """Initialize with an instance of the BaseEncryptionService.
        
        Args:
            encryption_service: Service instance for encrypting/decrypting values.
        """
        if not isinstance(encryption_service, BaseEncryptionService):
             raise TypeError("encryption_service must be an instance of BaseEncryptionService")
        self._encryption = encryption_service
    
    def encrypt_fields(self, data: dict[str, Any] | list[Any], fields: list[str]) -> dict[str, Any] | list[Any]:
        """Encrypt specific fields in a data structure (dict or list).
        
        Args:
            data: Data structure (dict or list) containing fields to encrypt.
            fields: List of field paths in dot notation (e.g., 'user.profile.email').
            
        Returns:
            A deep copy of the data structure with specified fields encrypted.
        """
        if not data or not fields:
            return data
            
        # Make a deep copy to avoid modifying the original
        result = copy.deepcopy(data)
        
        # Process each field path for encryption
        for field_path in fields:
            self._process_field(result, field_path, encrypt=True)
            
        return result
    
    def decrypt_fields(self, data: dict[str, Any] | list[Any], fields: list[str]) -> dict[str, Any] | list[Any]:
        """Decrypt specific fields in a data structure (dict or list).
        
        Args:
            data: Data structure (dict or list) with encrypted fields.
            fields: List of field paths in dot notation.
            
        Returns:
            A deep copy of the data structure with specified fields decrypted.
        """
        if not data or not fields:
            return data
            
        # Make a deep copy to avoid modifying the original
        result = copy.deepcopy(data)
        
        # Process each field path for decryption
        for field_path in fields:
            self._process_field(result, field_path, encrypt=False)
            
        return result
    
    def _process_field(self, data: dict[str, Any] | list[Any], field_path: str, encrypt: bool) -> None:
        """Recursively process a field path for encryption or decryption.

        Handles nested dictionaries and lists.
        
        Args:
            data: Current data structure segment (dict or list) being processed.
            field_path: Remaining field path in dot notation.
            encrypt: If True, encrypt the field; otherwise decrypt.
        """
        if not field_path:
            return
            
        parts = field_path.split('.', 1) # Split only the first part
        current_key = parts[0]
        remaining_path = parts[1] if len(parts) > 1 else None

        if isinstance(data, dict):
            if current_key in data:
                if remaining_path:
                    # Navigate deeper
                    self._process_field(data[current_key], remaining_path, encrypt)
                else:
                    # Reached the target field
                    value = data[current_key]
                    self._encrypt_or_decrypt_value(data, current_key, value, encrypt)
            # else: field not found in this dict, continue silently

        elif isinstance(data, list):
            # If the current key is a specific index
            if current_key.isdigit():
                index = int(current_key)
                if 0 <= index < len(data):
                    if remaining_path:
                         # Navigate deeper into the list element
                        self._process_field(data[index], remaining_path, encrypt)
                    else:
                         # Reached the target element (leaf node)
                        value = data[index]
                        # Use a temporary dict wrapper for _encrypt_or_decrypt_value 
                        temp_wrapper = {'value': value}
                        self._encrypt_or_decrypt_value(temp_wrapper, 'value', value, encrypt)
                        data[index] = temp_wrapper['value']
            else:
                 # Apply the entire path to each element if the key is not an index
                 # This handles cases like "items.name" where items is a list of dicts.
                 logger.debug(f"Applying path '{field_path}' to elements of list.")
                 for item in data:
                     if isinstance(item, (dict, list)): # Only process containers
                         self._process_field(item, field_path, encrypt)
        
        # else: data is not a dict or list, cannot navigate further

    def _encrypt_or_decrypt_value(self, obj: dict[str, Any], field: str, value: Any, encrypt: bool) -> None:
        """Encrypt or decrypt a specific field's value using the BaseEncryptionService.
        
        Modifies the `obj` dictionary in place.

        Args:
            obj: Dictionary containing the field.
            field: Field name to process.
            value: Current field value.
            encrypt: Whether to encrypt or decrypt.
        """
        if value is None:
            # Do not encrypt/decrypt None values
            return 
            
        try:
            if encrypt:
                 # Encrypt only if it's not already encrypted
                 if not (isinstance(value, str) and value.startswith(self._encryption.VERSION_PREFIX)):
                    encrypted_value = self._encryption.encrypt(value)
                    if encrypted_value is not None: # Check if encryption returned None
                        obj[field] = encrypted_value
                    else:
                        # Handle case where encryption returns None (e.g., input was None initially)
                        obj[field] = None 
                 else:
                     logger.debug(f"Value for field '{field}' appears already encrypted, skipping encryption.")
            else: # Decrypt
                if isinstance(value, str) and value.startswith(self._encryption.VERSION_PREFIX):
                    decrypted_value = self._encryption.decrypt(value)
                    obj[field] = decrypted_value
                # else: Value is not a string or doesn't have the prefix, assume not encrypted

        except (ValueError, TypeError) as e:
            op = "Encryption" if encrypt else "Decryption"
            logger.error(f"{op} error for field '{field}': {e}. Keeping original value.")
            # Keep original value in case of error during processing
            pass # Keep obj[field] as it was
    
    def encrypt_phi_fields(self, data: dict[str, Any], phi_fields: set[str]) -> dict[str, Any]:
        """Encrypt all PHI fields in a data structure.
        
        This is a convenience method for encrypting all PHI fields in a single call.
        
        Args:
            data: Data structure containing PHI fields.
            phi_fields: Set of PHI field names to encrypt.
            
        Returns:
            A copy of the data structure with PHI fields encrypted.
        """
        return self.encrypt_fields(data, list(phi_fields))
    
    def decrypt_phi_fields(self, data: dict[str, Any], phi_fields: set[str]) -> dict[str, Any]:
        """Decrypt all PHI fields in a data structure.
        
        This is a convenience method for decrypting all PHI fields in a single call.
        
        Args:
            data: Data structure containing encrypted PHI fields.
            phi_fields: Set of PHI field names to decrypt.
            
        Returns:
            A copy of the data structure with PHI fields decrypted.
        """
        return self.decrypt_fields(data, list(phi_fields))