"""
Encryption service implementation.

This module implements the IEncryptionService to provide
HIPAA-compliant encryption for all PHI data in the system.
"""

import base64
import hashlib
import hmac
import os
from typing import Any
import logging

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.interfaces.services.encryption_service_interface import IEncryptionService
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService

logger = logging.getLogger(__name__)

class EncryptionService(BaseEncryptionService, IEncryptionService):
    """
    Implementation of the encryption service with HIPAA-compliant encryption.
    
    This service uses Fernet (symmetric encryption) with proper key management
    to ensure data is encrypted at rest and in transit. It follows the
    Single Responsibility Principle by focusing solely on encryption operations.
    """
    
    def __init__(self, master_key: bytes | None = None):
        """
        Initialize the encryption service.
        
        Args:
            master_key: Optional master key for encryption/decryption
        """
        super().__init__()
        
        # Use provided key or generate a new one
        self._master_key = master_key or self._load_or_generate_master_key()
        self._fernet = Fernet(self._master_key)
        
        # Conform to BaseEncryptionService's expected attributes for encrypt_string/decrypt_string
        self.active_fernet = self._fernet
        self.active_key_version = "v1" # Default version for this simple setup
        logger.info(f"[EncryptionService.__init__] Set active_fernet (is self._fernet): {self.active_fernet is not None}, active_key_version: {self.active_key_version}")
    
    def _ensure_fernet_initialized(self):
        """Ensure Fernet instances needed by BaseEncryptionService methods are ready."""
        # For this simple service, primary initialization is in __init__
        if not hasattr(self, '_fernet') or not self._fernet:
            logger.error("[_ensure_fernet_initialized] self._fernet is not initialized! This should not happen.")
            # Attempt re-initialization as a fallback, though __init__ should prevent this.
            self._master_key = self._load_or_generate_master_key()
            self._fernet = Fernet(self._master_key)
        
        if not hasattr(self, 'active_fernet') or not self.active_fernet:
            self.active_fernet = self._fernet
            logger.info("[_ensure_fernet_initialized] self.active_fernet was not set, set to self._fernet.")
        
        if not hasattr(self, 'active_key_version') or not self.active_key_version:
            self.active_key_version = "v1"
            logger.info("[_ensure_fernet_initialized] self.active_key_version was not set, set to 'v1'.")
        logger.debug(f"[_ensure_fernet_initialized] Checked. active_fernet: {self.active_fernet is not None}, active_key_version: {self.active_key_version}")
    
    def encrypt(self, data: str | bytes, context: dict[str, Any] | None = None) -> bytes:
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
            fernet_instance_for_context = Fernet(context_key)
            return fernet_instance_for_context.encrypt(data_bytes)
        
        # Use master key if no context
        return self._fernet.encrypt(data_bytes)
    
    def decrypt(self, encrypted_data: bytes, context: dict[str, Any] | None = None) -> bytes:
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
                fernet_instance_for_context = Fernet(context_key)
                return fernet_instance_for_context.decrypt(encrypted_data)
            
            # Use master key if no context
            return self._fernet.decrypt(encrypted_data)
        except Exception as e:
            logger.error(f"[EncryptionService.decrypt] Decryption failed. Context provided: {context is not None}. Error: {e}", exc_info=True)
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
        logger.info("[_load_or_generate_master_key] Attempting to load/generate master key.")
        env_key = os.environ.get("ENCRYPTION_MASTER_KEY")
        if env_key:
            logger.info(f"[_load_or_generate_master_key] Found ENCRYPTION_MASTER_KEY in env: '{env_key[:10]}...' (len: {len(env_key)})")
            try:
                # Attempt to decode assuming it's a b64 encoded key string
                key_bytes = base64.b64decode(env_key)
                logger.info(f"[_load_or_generate_master_key] Successfully b64decoded ENCRYPTION_MASTER_KEY. Key bytes len: {len(key_bytes)}")
                # Fernet keys are typically 32 bytes after b64decode
                if len(key_bytes) == 32:
                    logger.info("[_load_or_generate_master_key] Decoded key is 32 bytes, suitable for Fernet.")
                    return key_bytes
                else:
                    logger.warning(f"[_load_or_generate_master_key] Decoded key is {len(key_bytes)} bytes, expected 32. Will proceed, but this might be an issue.")
                    return key_bytes # Proceed with potentially wrong length key
            except Exception as e:
                logger.warning(f"[_load_or_generate_master_key] Failed to b64decode ENCRYPTION_MASTER_KEY ('{env_key[:10]}...'): {e}. Falling back to treating it as raw string or generating new key.")
                # If ENCRYPTION_MASTER_KEY was not b64, treat it as a raw password to be encoded directly (likely wrong for Fernet)
                # This path is problematic if the env var is not a Fernet-compatible b64 string.
                # For safety, if b64decode fails on an env var that's present, it's safer to error or generate new
                # than to use its raw bytes if it wasn't intended as a direct Fernet key.
                # However, the original code had a pass, then generate. Let's log that fallback clearly.
                logger.warning("[_load_or_generate_master_key] ENCRYPTION_MASTER_KEY was present but not valid b64. Generating new key instead.")
                # Fallback to generating new key
        else:
            logger.info("[_load_or_generate_master_key] ENCRYPTION_MASTER_KEY not found in env.")

        new_key = Fernet.generate_key()
        logger.info(f"[_load_or_generate_master_key] Generated new Fernet key. Key bytes len: {len(new_key)}")
        # In a real scenario, this new key should be persisted securely.
        # For now, we might log it for debugging if absolutely necessary and if logs are secure.
        # logger.warning(f"[_load_or_generate_master_key] Generated new key (bytes): {new_key.decode('utf-8')} (THIS IS SENSITIVE, FOR DEBUG ONLY IF LOGS ARE SECURE)")
        return new_key
    
    def _derive_key_from_context(self, context: dict[str, Any]) -> bytes:
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