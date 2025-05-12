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

import numpy as np

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
    
    # Alias for test compatibility - encrypt_embedding (single) -> encrypt_embeddings (multiple)
    def encrypt_embedding(self, embedding: np.ndarray) -> str:
        """
        Encrypt a single embedding vector.
        
        Args:
            embedding: NumPy embedding vector
            
        Returns:
            Encrypted embedding string
            
        Raises:
            ValueError: If input is not a valid array
        """
        if embedding is None:
            return None
            
        # Check for valid embedding
        if not isinstance(embedding, np.ndarray):
            raise ValueError("Embedding must be a NumPy array")
            
        # Convert to list for JSON serialization and encrypt
        return self.encrypt_embeddings(embedding.tolist())
    
    def decrypt_embedding(self, encrypted_embedding: str) -> np.ndarray:
        """
        Decrypt a single embedding vector.
        
        Args:
            encrypted_embedding: Encrypted embedding string
            
        Returns:
            NumPy array with the embedding vector
        """
        if encrypted_embedding is None:
            return None
            
        # Decrypt and convert back to numpy array
        embedding_list = self.decrypt_embeddings(encrypted_embedding)
        return np.array(embedding_list)
        
    def encrypt_tensors(self, tensors: Dict[str, np.ndarray]) -> Dict[str, str]:
        """
        Encrypt a dictionary of tensor data.
        
        Args:
            tensors: Dictionary of tensor name to NumPy array
            
        Returns:
            Dictionary with encrypted tensors
        """
        if tensors is None:
            return None
            
        result = {}
        for key, tensor in tensors.items():
            if tensor is None:
                result[key] = None
            else:
                # Convert tensor to list for serialization
                tensor_list = tensor.tolist() if isinstance(tensor, np.ndarray) else tensor
                result[key] = self.encrypt_string(json.dumps(tensor_list))
                
        return result
        
    def decrypt_tensors(self, encrypted_tensors: Dict[str, str]) -> Dict[str, np.ndarray]:
        """
        Decrypt a dictionary of encrypted tensors.
        
        Args:
            encrypted_tensors: Dictionary of tensor name to encrypted string
            
        Returns:
            Dictionary with decrypted tensors as NumPy arrays
        """
        if encrypted_tensors is None:
            return None
            
        result = {}
        for key, encrypted_tensor in encrypted_tensors.items():
            if encrypted_tensor is None:
                result[key] = None
            else:
                # Decrypt and convert back to NumPy array
                tensor_json = self.decrypt_string(encrypted_tensor)
                tensor_list = json.loads(tensor_json)
                result[key] = np.array(tensor_list)
                
        return result
    
    def encrypt_ml_data(self, ml_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt machine learning data with intelligent field handling.
        
        This method analyzes the content to determine which fields need encryption:
        - Patient identifiers are always encrypted
        - Embeddings and feature vectors are encrypted
        - Model hyperparameters are generally not encrypted unless they contain PHI
        
        Args:
            ml_data: ML data dictionary with mixed content types
            
        Returns:
            Dictionary with selectively encrypted fields
        """
        if ml_data is None:
            return None
            
        result = {}
        
        # List of fields that should always be encrypted (potential PHI)
        sensitive_fields = {
            "patient_identifiers", "feature_names", "patient_data", 
            "demographics", "notes", "medical_history"
        }
        
        # List of fields that should never be encrypted (non-PHI)
        non_sensitive_fields = {
            "model_type", "version", "created_at", "updated_at", 
            "hyperparameters", "performance_metrics"
        }
        
        for key, value in ml_data.items():
            # Always encrypt sensitive fields
            if key in sensitive_fields:
                if isinstance(value, dict):
                    # For nested dictionaries, encrypt all values
                    result[key] = {k: self.encrypt_string(v) if isinstance(v, (str, int, float)) else 
                                   self.encrypt_string(json.dumps(v)) for k, v in value.items()}
                else:
                    # For simple values, encrypt directly
                    result[key] = self.encrypt_string(json.dumps(value))
                    
            # Never encrypt non-sensitive fields
            elif key in non_sensitive_fields:
                result[key] = value
                
            # Special handling for metadata
            elif key == "metadata":
                # Metadata might contain mixed sensitive/non-sensitive info
                if isinstance(value, dict):
                    result[key] = {k: self.encrypt_string(v) if k in ["author", "department", "notes"] else v 
                                  for k, v in value.items()}
                else:
                    result[key] = value
                    
            # Special handling for embeddings
            elif key == "embeddings":
                if isinstance(value, dict):
                    # For dictionary of embeddings, encrypt each one
                    result[key] = {k: self.encrypt_embeddings(v) for k, v in value.items()}
                else:
                    # For single embedding value
                    result[key] = self.encrypt_embeddings(value)
                    
            # Default: encrypt if it looks like PHI based on field name
            elif any(phi_term in key.lower() for phi_term in ["patient", "name", "id", "ssn", "address", "phone", "email", "dob"]):
                result[key] = self.encrypt_string(json.dumps(value))
                
            # Otherwise, keep as is
            else:
                result[key] = value
                
        return result
        
    def decrypt_ml_data(self, encrypted_ml_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt machine learning data that was encrypted with encrypt_ml_data.
        
        Args:
            encrypted_ml_data: Dictionary with encrypted ML data
            
        Returns:
            Dictionary with decrypted ML data
        """
        if encrypted_ml_data is None:
            return None
            
        result = {}
        
        # Handle different field types based on naming and content
        for key, value in encrypted_ml_data.items():
            # Handle nested dictionaries
            if isinstance(value, dict):
                # Check if it's an encrypted embedding dictionary
                if key == "embeddings":
                    result[key] = {k: np.array(json.loads(self.decrypt_string(v))) 
                                  if v and isinstance(v, str) and v.startswith(self.VERSION_PREFIX)
                                  else v for k, v in value.items()}
                elif key == "metadata":
                    # Metadata may have encrypted fields
                    result[key] = {k: self.decrypt_string(v) 
                                  if v and isinstance(v, str) and v.startswith(self.VERSION_PREFIX)
                                  else v for k, v in value.items()}
                elif key == "patient_data":
                    # Patient data is fully encrypted
                    result[key] = {k: self.decrypt_string(v) 
                                  if v and isinstance(v, str) and v.startswith(self.VERSION_PREFIX)
                                  else v for k, v in value.items()}
                else:
                    # Default dictionary handling
                    result[key] = value
            
            # Handle string values that might be encrypted
            elif isinstance(value, str) and value.startswith(self.VERSION_PREFIX):
                try:
                    # Try to decrypt and parse as JSON if possible
                    decrypted = self.decrypt_string(value)
                    if decrypted.startswith("[") or decrypted.startswith("{"):
                        try:
                            # Parse as JSON
                            parsed = json.loads(decrypted)
                            
                            # Convert lists to numpy arrays for certain fields
                            if key in ["feature_names", "patient_identifiers"]:
                                result[key] = parsed
                            elif key == "embeddings":
                                # Convert to numpy array if it's a list of numbers
                                if isinstance(parsed, list) and all(isinstance(x, (int, float)) for x in parsed):
                                    result[key] = np.array(parsed)
                                else:
                                    result[key] = parsed
                            else:
                                result[key] = parsed
                        except json.JSONDecodeError:
                            # Not JSON, use as is
                            result[key] = decrypted
                    else:
                        # Not JSON, use as is
                        result[key] = decrypted
                except Exception as e:
                    # If decryption fails, keep the original value
                    logger.error(f"Failed to decrypt field {key}: {str(e)}")
                    result[key] = value
            else:
                # Non-encrypted values pass through
                result[key] = value
                
        return result
    
    def encrypt_model_file(self, model_file_path: str) -> str:
        """
        Encrypt an ML model file on disk.
        
        Args:
            model_file_path: Path to the model file to encrypt
            
        Returns:
            Path to the encrypted model file (original_path + .enc)
            
        Raises:
            FileNotFoundError: If the model file doesn't exist
            IOError: If file operations fail
        """
        if not os.path.exists(model_file_path):
            raise FileNotFoundError(f"Model file not found: {model_file_path}")
            
        encrypted_path = f"{model_file_path}.enc"
        
        try:
            # Read the model file in chunks to handle large files
            with open(model_file_path, 'rb') as in_file, open(encrypted_path, 'wb') as out_file:
                # Write the version prefix
                out_file.write(self.VERSION_PREFIX.encode())
                
                # Generate file checksum for integrity verification
                checksum = hashlib.sha256()
                
                # Process the file in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                while True:
                    chunk = in_file.read(chunk_size)
                    if not chunk:
                        break
                        
                    # Update checksum
                    checksum.update(chunk)
                    
                    # Encrypt and write chunk
                    encrypted_chunk = self.cipher.encrypt(chunk)
                    out_file.write(encrypted_chunk)
                    
                # Write the checksum at the end
                out_file.write(b"##CHECKSUM##")
                out_file.write(checksum.digest())
                
            return encrypted_path
            
        except Exception as e:
            logger.error(f"Failed to encrypt model file: {str(e)}")
            # Clean up partial file if encryption failed
            if os.path.exists(encrypted_path):
                os.unlink(encrypted_path)
            raise IOError(f"Model file encryption failed: {str(e)}")
    
    def decrypt_model_file(self, encrypted_file_path: str) -> str:
        """
        Decrypt an ML model file that was encrypted with encrypt_model_file.
        
        Args:
            encrypted_file_path: Path to the encrypted model file
            
        Returns:
            Path to the decrypted model file (original_path with .enc removed or .dec added)
            
        Raises:
            FileNotFoundError: If the encrypted file doesn't exist
            ValueError: If the file isn't a valid encrypted model file
            IOError: If file operations fail
        """
        if not os.path.exists(encrypted_file_path):
            raise FileNotFoundError(f"Encrypted model file not found: {encrypted_file_path}")
            
        # Determine output path
        if encrypted_file_path.endswith(".enc"):
            decrypted_path = encrypted_file_path[:-4]
        else:
            decrypted_path = f"{encrypted_file_path}.dec"
            
        try:
            with open(encrypted_file_path, 'rb') as in_file, open(decrypted_path, 'wb') as out_file:
                # Read and verify the version prefix
                prefix = in_file.read(len(self.VERSION_PREFIX))
                if prefix.decode() != self.VERSION_PREFIX:
                    raise ValueError(f"Invalid encrypted model file: missing version prefix")
                    
                # Read file in chunks
                calculated_checksum = hashlib.sha256()
                while True:
                    # Read an encrypted chunk
                    chunk = in_file.read(1024 * 1024 + 32)  # Account for encryption overhead
                    
                    # Check if we've reached the checksum marker
                    if b"##CHECKSUM##" in chunk:
                        # Split at the checksum marker
                        data_part, checksum_part = chunk.split(b"##CHECKSUM##", 1)
                        
                        # Decrypt the last data chunk if any
                        if data_part:
                            decrypted_chunk = self.cipher.decrypt(data_part)
                            out_file.write(decrypted_chunk)
                            calculated_checksum.update(decrypted_chunk)
                            
                        # Verify checksum
                        if checksum_part != calculated_checksum.digest():
                            raise ValueError("Model file integrity check failed: checksum mismatch")
                            
                        break
                        
                    # EOF without checksum marker
                    if not chunk:
                        raise ValueError("Model file integrity check failed: missing checksum")
                        
                    # Normal chunk processing
                    decrypted_chunk = self.cipher.decrypt(chunk)
                    out_file.write(decrypted_chunk)
                    calculated_checksum.update(decrypted_chunk)
                    
            return decrypted_path
            
        except Exception as e:
            logger.error(f"Failed to decrypt model file: {str(e)}")
            # Clean up partial file if decryption failed
            if os.path.exists(decrypted_path):
                os.unlink(decrypted_path)
            raise ValueError(f"Model file decryption failed: {str(e)}")
    
    def encrypt_phi_safe_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt data with PHI fields selectively encrypted.
        
        This method intelligently encrypts only the fields that might contain PHI,
        while leaving non-PHI fields unencrypted for better performance.
        
        Args:
            data: Dictionary of mixed PHI and non-PHI fields
            
        Returns:
            Dictionary with PHI fields encrypted
        """
        if data is None:
            return None
            
        result = {}
        
        # Fields that might contain PHI
        phi_patterns = [
            "name", "patient", "address", "phone", "email", "ssn", "social", "dob", "birth", 
            "age", "zip", "location", "mrn", "medical_record", "contact", "provider", "physician",
            "diagnosis", "condition", "treatment", "medication", "notes", "visit"
        ]
        
        for key, value in data.items():
            # Check if this field might contain PHI
            is_phi = any(pattern in key.lower() for pattern in phi_patterns)
            
            if is_phi:
                # Encrypt PHI fields
                if isinstance(value, dict):
                    # Recursively encrypt nested dictionaries
                    result[key] = self.encrypt_phi_safe_data(value)
                elif isinstance(value, list):
                    # For lists, encrypt each item if it might contain PHI
                    result[key] = [
                        self.encrypt_phi_safe_data(item) if isinstance(item, dict)
                        else self.encrypt_string(item)
                        for item in value
                    ]
                else:
                    # Encrypt simple values
                    result[key] = self.encrypt_string(value)
            else:
                # Non-PHI fields remain unchanged
                result[key] = value
                
        return result

    def encrypt_embeddings(self, embeddings: List[float]) -> str:
        """
        Encrypt vector embeddings for secure storage.
        
        Args:
            embeddings: List of floating point embedding values or NumPy array
            
        Returns:
            Encrypted embedding string
            
        Raises:
            ValueError: If encryption fails
        """
        if embeddings is None:
            return None
        
        try:
            # Convert NumPy arrays to lists for JSON serialization
            if hasattr(embeddings, 'tolist'):
                embeddings_list = embeddings.tolist()
            else:
                embeddings_list = embeddings
            
            # Convert to JSON
            embeddings_json = json.dumps(embeddings_list)
            
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
            return None
        
        try:
            # Decrypt with standard method
            decrypted_json = self.decrypt_string(encrypted_embeddings)
            
            # Parse JSON to list
            return json.loads(decrypted_json)
        except Exception as e:
            logger.error(f"Embedding decryption failed: {str(e)}")
            raise ValueError(f"Failed to decrypt embeddings: {str(e)}")

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