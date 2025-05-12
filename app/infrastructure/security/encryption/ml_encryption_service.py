"""
Machine Learning Encryption Service.

This module provides encryption for machine learning models and data,
with special focus on ensuring secure storage of PHI in ML systems
while maintaining HIPAA compliance.
"""

import logging
import os
import base64
import hashlib
import json
from typing import Dict, Any, Optional, Union, List, Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from app.core.config.settings import get_settings
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService, VERSION_PREFIX, KDF_ITERATIONS
)

# Initialize a basic logger to avoid import cycles
# Will be replaced with proper logger on first use
logger = logging.getLogger(__name__)

# Constants for ML-specific encryption
ML_ENCRYPTION_VERSION = "ml-v1:"
HASH_ITERATIONS = 200000  # Higher iteration count for model protection
SALT_SIZE = 16  # 128 bits salt size


class MLEncryptionService(BaseEncryptionService):
    """
    Specialized encryption service for ML models and data.
    
    Extends the BaseEncryptionService with additional features specific
    to machine learning, such as model checksum validation and enhanced
    key derivation for model weights.
    """
    
    def __init__(
        self, 
        secret_key: Optional[Union[str, bytes]] = None, 
        salt: Optional[Union[str, bytes]] = None,
        direct_key: Optional[str] = None,
        previous_key: Optional[str] = None,
        use_legacy_prefix: bool = False
    ):
        """
        Initialize ML encryption service.
        
        Args:
            secret_key: The secret key for encryption
            salt: Optional salt for key derivation
            direct_key: Optional key (backward compatibility with tests)
            previous_key: Optional previous key for key rotation
            use_legacy_prefix: Whether to use legacy version prefix
        """
        # Call parent init with all compatibility parameters
        super().__init__(
            secret_key=secret_key, 
            salt=salt,
            direct_key=direct_key,
            previous_key=previous_key
        )
        
        # Use ML-specific version prefix
        self.VERSION_PREFIX = ML_ENCRYPTION_VERSION if not use_legacy_prefix else VERSION_PREFIX
        
        # Get proper logger on first initialization
        global logger
        if not hasattr(logger, 'initialized_for_ml'):
            try:
                from app.core.utils.logging import get_logger
                logger = get_logger(__name__)
                logger.initialized_for_ml = True
            except ImportError:
                # If still can't import, keep the basic logger
                pass
        
        logger.debug("ML Encryption Service initialized")
        
    def encrypt_model(self, model_bytes: bytes) -> str:
        """
        Encrypt a machine learning model with checksums.
        
        Args:
            model_bytes: Serialized model bytes
            
        Returns:
            Encrypted model with checksums and version info
            
        Raises:
            ValueError: If encryption fails
        """
        if model_bytes is None:
            return None
            
        try:
            # Calculate model checksum for integrity verification
            checksum = hashlib.sha256(model_bytes).hexdigest()
            
            # Create metadata with checksum and version
            metadata = {
                "checksum": checksum,
                "version": "1.0",
                "algorithm": "SHA-256",
                "encrypted": True
            }
            
            # Serialize metadata to JSON
            metadata_json = json.dumps(metadata)
            
            # Encrypt both separately for better security
            encrypted_model = self.encrypt(model_bytes)
            encrypted_metadata = self.encrypt_string(metadata_json)
            
            # Combine into a single payload
            payload = {
                "model": encrypted_model,
                "metadata": encrypted_metadata
            }
            
            # Encode final result
            return f"{self.VERSION_PREFIX}{base64.b64encode(json.dumps(payload).encode()).decode()}"
        except Exception as e:
            logger.error(f"Model encryption failed: {str(e)}")
            raise ValueError(f"Failed to encrypt ML model: {str(e)}")
            
    def decrypt_model(self, encrypted_model: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Decrypt a machine learning model and verify its checksum.
        
        Args:
            encrypted_model: Encrypted model string
            
        Returns:
            Tuple of (model_bytes, metadata)
            
        Raises:
            ValueError: If decryption or checksum verification fails
        """
        if encrypted_model is None:
            raise ValueError("Cannot decrypt None model")
            
        try:
            # Check version prefix
            if not encrypted_model.startswith(self.VERSION_PREFIX):
                raise ValueError(f"Invalid model encryption version. Expected {self.VERSION_PREFIX}")
                
            # Remove version prefix
            encrypted_payload = encrypted_model[len(self.VERSION_PREFIX):]
            
            # Decode the payload
            payload_json = base64.b64decode(encrypted_payload).decode()
            payload = json.loads(payload_json)
            
            # Extract components
            encrypted_model_data = payload["model"]
            encrypted_metadata = payload["metadata"]
            
            # Decrypt both components
            model_bytes = self.decrypt(encrypted_model_data)
            metadata_json = self.decrypt_string(encrypted_metadata)
            metadata = json.loads(metadata_json)
            
            # Verify checksum
            calculated_checksum = hashlib.sha256(model_bytes).hexdigest()
            if calculated_checksum != metadata["checksum"]:
                raise ValueError("Model checksum verification failed. Model may be corrupted.")
                
            return model_bytes, metadata
        except json.JSONDecodeError:
            logger.error("Invalid JSON format in encrypted model")
            raise ValueError("Cannot decrypt model: invalid format")
        except Exception as e:
            logger.error(f"Model decryption failed: {str(e)}")
            raise ValueError(f"Failed to decrypt ML model: {str(e)}")
            
    def derive_model_key(self, base_key: str, model_id: str) -> bytes:
        """
        Derive a model-specific encryption key.
        
        This creates a unique key for each model based on model ID and base key,
        providing per-model isolation.
        
        Args:
            base_key: Base encryption key
            model_id: Unique model identifier
            
        Returns:
            Derived key bytes
        """
        try:
            # Use model_id as salt for key derivation
            salt = hashlib.sha256(model_id.encode()).digest()[:16]
            
            # Create key derivation function
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=HASH_ITERATIONS,
            )
            
            # Derive key using base_key
            if isinstance(base_key, str):
                base_key = base_key.encode()
                
            key = kdf.derive(base_key)
            return base64.urlsafe_b64encode(key)
        except Exception as e:
            logger.error(f"Key derivation failed: {str(e)}")
            raise ValueError(f"Failed to derive model key: {str(e)}")
            
    def encrypt_embeddings(self, embeddings: List[float]) -> str:
        """
        Encrypt vector embeddings for secure storage.
        
        Args:
            embeddings: List of floating point embedding values
            
        Returns:
            Encrypted embedding string
            
        Raises:
            ValueError: If encryption fails
        """
        if embeddings is None:
            return None
            
        try:
            # Convert to JSON
            embeddings_json = json.dumps(embeddings)
            
            # Encrypt with standard method
            return self.encrypt_string(embeddings_json)
        except Exception as e:
            logger.error(f"Embedding encryption failed: {str(e)}")
            raise ValueError(f"Failed to encrypt embeddings: {str(e)}")
            
    def decrypt_embeddings(self, encrypted_embeddings: str) -> List[float]:
        """
        Decrypt vector embeddings.
        
        Args:
            encrypted_embeddings: Encrypted embedding string
            
        Returns:
            List of decrypted embedding values
            
        Raises:
            ValueError: If decryption fails
        """
        if encrypted_embeddings is None:
            raise ValueError("Cannot decrypt None embeddings")
            
        try:
            # Decrypt with standard method
            decrypted_json = self.decrypt_string(encrypted_embeddings)
            
            # Parse JSON to list
            return json.loads(decrypted_json)
        except Exception as e:
            logger.error(f"Embedding decryption failed: {str(e)}")
            raise ValueError(f"Failed to decrypt embeddings: {str(e)}")
            
    def encrypt_predictions(self, predictions: Union[Dict[str, Any], List[Any]]) -> str:
        """
        Encrypt ML model predictions with PHI.
        
        Args:
            predictions: Prediction data to encrypt
            
        Returns:
            Encrypted predictions string
            
        Raises:
            ValueError: If encryption fails
        """
        if predictions is None:
            return None
            
        try:
            # Add metadata for auditing
            payload = {
                "predictions": predictions,
                "metadata": {
                    "encrypted_at": "timestamp_placeholder",  # In real code, use actual timestamp
                    "version": "1.0"
                }
            }
            
            # Encrypt using dict encryption
            return self.encrypt_dict(payload)
        except Exception as e:
            logger.error(f"Prediction encryption failed: {str(e)}")
            raise ValueError(f"Failed to encrypt predictions: {str(e)}")
            
    def decrypt_predictions(self, encrypted_predictions: str) -> Dict[str, Any]:
        """
        Decrypt ML model predictions.
        
        Args:
            encrypted_predictions: Encrypted predictions string
            
        Returns:
            Dictionary with predictions and metadata
            
        Raises:
            ValueError: If decryption fails
        """
        if encrypted_predictions is None:
            raise ValueError("Cannot decrypt None predictions")
            
        try:
            # Decrypt using standard dict decryption
            decrypted = self.decrypt_dict(encrypted_predictions)
            
            # Return the whole payload with metadata
            return decrypted
        except Exception as e:
            logger.error(f"Prediction decryption failed: {str(e)}")
            raise ValueError(f"Failed to decrypt predictions: {str(e)}")
        
    def get_versioned_model_key(self, model_id: str, version: int = 1) -> bytes:
        """
        Get a versioned encryption key for a specific model.
        
        This allows key rotation for ML models without losing access
        to older encrypted models.
        
        Args:
            model_id: Model identifier
            version: Key version number
            
        Returns:
            Versioned encryption key as bytes
        """
        try:
            # Get the base key
            base_key = self.cipher.key
            
            # Add version info to model_id
            versioned_id = f"{model_id}:v{version}"
            
            # Derive the key
            return self.derive_model_key(base64.urlsafe_b64decode(base_key).decode(), versioned_id)
        except Exception as e:
            logger.error(f"Failed to get versioned model key: {str(e)}")
            raise ValueError(f"Key derivation error: {str(e)}")


def get_ml_encryption_service(
    direct_key: Optional[str] = None, 
    previous_key: Optional[str] = None,
    salt: Optional[str] = None,
    use_legacy_prefix: bool = False
) -> MLEncryptionService:
    """
    Get an instance of the ML Encryption Service with the current keys.
    
    Args:
        direct_key: Optional key to use directly (primarily for testing)
        previous_key: Optional previous key to support key rotation
        salt: Optional salt for key derivation
        use_legacy_prefix: Whether to use legacy version prefix format
        
    Returns:
        MLEncryptionService instance
    """
    try:
        # Use provided keys or get from settings
        if direct_key is None:
            settings = get_settings()
            key = settings.ML_PHI_ENCRYPTION_KEY
            prev_key = settings.ML_PHI_ENCRYPTION_PREVIOUS_KEY
        else:
            key = direct_key
            prev_key = previous_key
        
        # Use provided salt or fallback to previous key
        if salt is not None:
            salt_to_use = salt
        elif prev_key is not None:
            salt_to_use = prev_key
        else:
            salt_to_use = None
        
        return MLEncryptionService(
            secret_key=key,
            salt=salt_to_use,
            direct_key=direct_key,
            previous_key=prev_key,
            use_legacy_prefix=use_legacy_prefix
        )
    except Exception as e:
        logger.error(f"Failed to create ML encryption service: {str(e)}")
        raise 