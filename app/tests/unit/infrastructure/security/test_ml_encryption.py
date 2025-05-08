"""
Unit tests for the ML encryption service.

These tests verify HIPAA-compliant encryption for ML models, tensors, and embeddings.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from app.infrastructure.security.encryption.ml_encryption_service import (
    MLEncryptionService,
    get_ml_encryption_service
)


@pytest.fixture
def ml_encryption_service():
    """Create an ML encryption service instance with a test key."""
    return MLEncryptionService(direct_key="test_ml_encryption_key_for_unit_tests_only_")


@pytest.fixture
def test_embedding():
    """Create a test embedding vector."""
    return np.array([0.1, 0.2, 0.3, 0.4, 0.5], dtype=np.float32)


@pytest.fixture
def test_tensors():
    """Create test tensors dictionary."""
    return {
        "embedding1": np.array([0.1, 0.2, 0.3], dtype=np.float32),
        "embedding2": np.array([0.4, 0.5, 0.6], dtype=np.float32),
        "matrix": np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float64),
        "empty": None
    }


@pytest.fixture
def test_ml_data():
    """Create test ML data with mixed types and potential PHI."""
    return {
        "model_type": "sentiment_analysis",
        "feature_names": ["patient_name", "condition", "medication", "notes"],
        "embeddings": {
            "text": np.array([0.1, 0.2, 0.3], dtype=np.float32),
            "metadata": np.array([0.4, 0.5, 0.6], dtype=np.float32)
        },
        "patient_identifiers": ["P12345", "P67890"],
        "metadata": {
            "author": "Dr. Jane Smith",
            "created_at": "2023-01-15T12:30:00Z",
            "department": "Psychiatry"
        },
        "hyperparameters": {
            "learning_rate": 0.01,
            "epochs": 100,
            "batch_size": 32
        }
    }


@pytest.fixture
def temp_model_file():
    """Create a temporary model file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Create a dummy model file with some content
        tmp.write(b"This is a mock ML model file for testing encryption")
    
    yield tmp.name
    
    # Clean up after the test
    if os.path.exists(tmp.name):
        os.remove(tmp.name)
    if os.path.exists(f"{tmp.name}.enc"):
        os.remove(f"{tmp.name}.enc")
    if os.path.exists(f"{tmp.name}.dec"):
        os.remove(f"{tmp.name}.dec")


@pytest.fixture
def large_temp_model_file():
    """Create a large temporary model file to test chunking."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Create a 15MB dummy model file
        tmp.write(b"X" * (15 * 1024 * 1024))
    
    yield tmp.name
    
    # Clean up after the test
    if os.path.exists(tmp.name):
        os.remove(tmp.name)
    if os.path.exists(f"{tmp.name}.enc"):
        os.remove(f"{tmp.name}.enc")
    if os.path.exists(f"{tmp.name}.dec"):
        os.remove(f"{tmp.name}.dec")


class TestMLEncryptionService:
    """Test suite for ML encryption service."""
    
    def test_encrypt_decrypt_embedding(self, ml_encryption_service, test_embedding):
        """Test encryption and decryption of embedding vectors."""
        # Encrypt the embedding
        encrypted_embedding = ml_encryption_service.encrypt_embedding(test_embedding)
        
        # Verify encryption result
        assert encrypted_embedding.startswith("v1:")
        assert "=" in encrypted_embedding  # Base64 padding
        
        # Decrypt the embedding
        decrypted_embedding = ml_encryption_service.decrypt_embedding(encrypted_embedding)
        
        # Verify decryption result
        assert isinstance(decrypted_embedding, np.ndarray)
        assert decrypted_embedding.shape == test_embedding.shape
        assert decrypted_embedding.dtype == test_embedding.dtype
        assert np.allclose(decrypted_embedding, test_embedding)
    
    def test_encrypt_decrypt_tensors(self, ml_encryption_service, test_tensors):
        """Test encryption and decryption of tensor dictionaries."""
        # Encrypt tensors
        encrypted_tensors = ml_encryption_service.encrypt_tensors(test_tensors)
        
        # Verify encryption results
        assert isinstance(encrypted_tensors, dict)
        assert set(encrypted_tensors.keys()) == set(test_tensors.keys())
        
        # Check each encrypted tensor
        for key, encrypted_value in encrypted_tensors.items():
            if test_tensors[key] is None:
                assert encrypted_value is None
            else:
                assert encrypted_value.startswith("v1:")
        
        # Decrypt tensors
        decrypted_tensors = ml_encryption_service.decrypt_tensors(encrypted_tensors)
        
        # Verify decryption results
        assert isinstance(decrypted_tensors, dict)
        assert set(decrypted_tensors.keys()) == set(test_tensors.keys())
        
        # Check each decrypted tensor
        for key, original_tensor in test_tensors.items():
            if original_tensor is None:
                assert decrypted_tensors[key] is None
            else:
                decrypted_tensor = decrypted_tensors[key]
                assert isinstance(decrypted_tensor, np.ndarray)
                assert decrypted_tensor.shape == original_tensor.shape
                assert decrypted_tensor.dtype == original_tensor.dtype
                assert np.allclose(decrypted_tensor, original_tensor)
    
    def test_encrypt_decrypt_ml_data(self, ml_encryption_service, test_ml_data):
        """Test encryption and decryption of ML data with mixed types."""
        # Encrypt ML data
        encrypted_data = ml_encryption_service.encrypt_ml_data(test_ml_data)
        
        # Verify encryption results
        assert isinstance(encrypted_data, dict)
        assert set(encrypted_data.keys()) == set(test_ml_data.keys())
        
        # Check that sensitive fields are encrypted
        assert encrypted_data["feature_names"].startswith("v1:")
        assert encrypted_data["patient_identifiers"].startswith("v1:")
        assert encrypted_data["metadata"].startswith("v1:")
        
        # Check that non-sensitive fields are not encrypted
        assert encrypted_data["model_type"] == "sentiment_analysis"
        assert isinstance(encrypted_data["hyperparameters"], dict)
        assert encrypted_data["hyperparameters"]["learning_rate"] == 0.01
        
        # Check nested encryption for embeddings
        assert isinstance(encrypted_data["embeddings"], dict)
        assert encrypted_data["embeddings"]["text"].startswith("v1:")
        assert encrypted_data["embeddings"]["metadata"].startswith("v1:")
        
        # Decrypt ML data
        decrypted_data = ml_encryption_service.decrypt_ml_data(encrypted_data)
        
        # Verify decryption results
        assert isinstance(decrypted_data, dict)
        assert set(decrypted_data.keys()) == set(test_ml_data.keys())
        
        # Check that sensitive fields are properly decrypted
        assert decrypted_data["feature_names"] == test_ml_data["feature_names"]
        assert decrypted_data["patient_identifiers"] == test_ml_data["patient_identifiers"]
        
        # Check nested decryption for embeddings
        embeddings = decrypted_data["embeddings"]
        assert isinstance(embeddings, dict)
        assert np.allclose(embeddings["text"], test_ml_data["embeddings"]["text"])
        assert np.allclose(embeddings["metadata"], test_ml_data["embeddings"]["metadata"])
        
        # Verify metadata decryption
        assert decrypted_data["metadata"]["author"] == test_ml_data["metadata"]["author"]
        assert decrypted_data["metadata"]["department"] == test_ml_data["metadata"]["department"]
        
        # Verify non-sensitive fields remain unchanged
        assert decrypted_data["model_type"] == test_ml_data["model_type"]
        assert decrypted_data["hyperparameters"]["learning_rate"] == test_ml_data["hyperparameters"]["learning_rate"]
    
    def test_encrypt_decrypt_model_file(self, ml_encryption_service, temp_model_file):
        """Test encryption and decryption of model files."""
        # Get the original file content for comparison
        with open(temp_model_file, "rb") as f:
            original_content = f.read()
            
        # Encrypt the model file
        encrypted_path = ml_encryption_service.encrypt_model(temp_model_file)
        
        # Verify encryption result
        assert os.path.exists(encrypted_path)
        assert os.path.getsize(encrypted_path) > os.path.getsize(temp_model_file)
        
        # Decrypt the model file with a new path
        decrypted_path = ml_encryption_service.decrypt_model(
            encrypted_path, output_path=f"{temp_model_file}.dec"
        )
        
        # Verify decryption result
        assert os.path.exists(decrypted_path)
        
        # Verify file content matches original
        with open(decrypted_path, "rb") as f:
            decrypted_content = f.read()
            
        assert decrypted_content == original_content
    
    def test_large_model_chunking(self, ml_encryption_service, large_temp_model_file):
        """Test chunked encryption and decryption of large model files."""
        # Get original file size for verification
        original_size = os.path.getsize(large_temp_model_file)
        assert original_size > 10 * 1024 * 1024  # Confirm it's larger than chunk size
        
        # Get file hash for content comparison
        import hashlib
        with open(large_temp_model_file, "rb") as f:
            original_hash = hashlib.md5(f.read()).hexdigest()
            
        # Encrypt the large model file
        encrypted_path = ml_encryption_service.encrypt_model(large_temp_model_file)
        
        # Verify encryption result
        assert os.path.exists(encrypted_path)
        assert os.path.getsize(encrypted_path) > original_size
        
        # Decrypt the model file
        decrypted_path = ml_encryption_service.decrypt_model(
            encrypted_path, output_path=f"{large_temp_model_file}.dec"
        )
        
        # Verify decryption result
        assert os.path.exists(decrypted_path)
        
        # Verify file hash matches original
        with open(decrypted_path, "rb") as f:
            decrypted_hash = hashlib.md5(f.read()).hexdigest()
            
        assert decrypted_hash == original_hash
    
    def test_handle_invalid_embedding(self, ml_encryption_service):
        """Test handling of invalid embedding inputs."""
        # None value should return None
        assert ml_encryption_service.encrypt_embedding(None) is None
        
        # Non-numpy array should raise ValueError
        with pytest.raises(ValueError):
            ml_encryption_service.encrypt_embedding([0.1, 0.2, 0.3])
            
        # Invalid encrypted string should raise ValueError
        with pytest.raises(ValueError):
            ml_encryption_service.decrypt_embedding("not-encrypted")
            
        # None value for decrypt should return None
        assert ml_encryption_service.decrypt_embedding(None) is None
            
    def test_key_rotation_for_embeddings(self):
        """Test key rotation for embeddings."""
        # Create service with old key
        old_service = MLEncryptionService(direct_key="ml_old_key_for_rotation_test_1234567890")
        
        # Create service with new key that knows about the old key
        new_service = MLEncryptionService(
            direct_key="ml_new_key_for_rotation_test_0987654321",
            previous_key="ml_old_key_for_rotation_test_1234567890"
        )
        
        # Create test data
        test_embedding = np.array([1.0, 2.0, 3.0, 4.0], dtype=np.float32)
        
        # Encrypt with old key
        encrypted_with_old = old_service.encrypt_embedding(test_embedding)
        
        # New service should be able to decrypt data encrypted with old key
        decrypted_with_new = new_service.decrypt_embedding(encrypted_with_old)
        assert np.allclose(decrypted_with_new, test_embedding)
        
        # New service encrypts with new key
        encrypted_with_new = new_service.encrypt_embedding(test_embedding)
        
        # Old service should NOT be able to decrypt data encrypted with new key
        with pytest.raises(ValueError):
            old_service.decrypt_embedding(encrypted_with_new)
    
    def test_get_ml_encryption_service(self):
        """Test the factory function for getting ML encryption service."""
        # Test with direct key
        service = get_ml_encryption_service(direct_key="test_direct_key")
        assert isinstance(service, MLEncryptionService)
        
        # Test with both keys
        service = get_ml_encryption_service(
            direct_key="test_direct_key",
            previous_key="test_previous_key"
        )
        assert isinstance(service, MLEncryptionService)
        
        # Test without keys (should use settings)
        with patch("app.core.config.settings.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                PHI_ENCRYPTION_KEY="test_phi_key_from_settings"
            )
            service = get_ml_encryption_service()
            assert isinstance(service, MLEncryptionService)


class TestMLSecurityCompliance:
    """Test suite for HIPAA security compliance aspects of ML encryption."""
    
    def test_phi_field_protection(self, ml_encryption_service):
        """Test protection of PHI fields in ML data."""
        # Create data with PHI
        phi_data = {
            "feature_names": ["patient_name", "age", "diagnosis"],
            "patient_data": {
                "name": "John Smith",
                "ssn": "123-45-6789",
                "medical_record": "Patient has anxiety disorder"
            },
            "model_config": {
                "version": "1.0.0",
                "created_by": "data_scientist@example.com"
            }
        }
        
        # Encrypt the data
        encrypted_data = ml_encryption_service.encrypt_ml_data(phi_data)
        
        # Verify PHI fields are encrypted
        assert encrypted_data["feature_names"].startswith("v1:")
        assert isinstance(encrypted_data["patient_data"], dict)
        assert all(value.startswith("v1:") for value in encrypted_data["patient_data"].values())
        
        # Non-PHI fields should not be encrypted
        assert isinstance(encrypted_data["model_config"], dict)
        assert encrypted_data["model_config"]["version"] == "1.0.0"
        
        # Convert to JSON to simulate serialization for storage/transmission
        json_data = json.dumps(encrypted_data, default=lambda x: str(x))
        
        # Verify no PHI is exposed in the serialized data
        assert "John Smith" not in json_data
        assert "123-45-6789" not in json_data
        assert "anxiety disorder" not in json_data
        
        # But encrypted tokens should be present
        assert "v1:" in json_data
    
    def test_error_message_phi_protection(self, ml_encryption_service):
        """Test protection of PHI in error messages."""
        # Create a corrupt/invalid encrypted embedding
        valid_encrypted = ml_encryption_service.encrypt_embedding(np.array([0.1, 0.2, 0.3]))
        corrupt_encrypted = valid_encrypted[:-10] + "CORRUPTED=="
        
        # Attempt to decrypt corrupted data and capture the error
        with pytest.raises(ValueError) as exc_info:
            ml_encryption_service.decrypt_embedding(corrupt_encrypted)
            
        # Check error message doesn't leak encrypted content
        error_message = str(exc_info.value)
        assert "Failed to decrypt embedding" in error_message
        assert corrupt_encrypted not in error_message
        assert "CORRUPTED" not in error_message
        
        # Similarly for ML data with corrupt fields
        corrupt_ml_data = {
            "embedding": valid_encrypted,
            "feature_names": corrupt_encrypted
        }
        
        # Should handle gracefully without exposing PHI
        decrypted_data = ml_encryption_service.decrypt_ml_data(corrupt_ml_data)
        assert decrypted_data["embedding"] is not None
        assert decrypted_data["feature_names"] is None  # Failed decryption becomes None


def test_version_compatibility():
    """Test version compatibility for encrypted data."""
    # Create service with standard version prefix
    service = MLEncryptionService(direct_key="test_version_compat_key_12345")
    
    # Create test data
    test_data = np.array([1.0, 2.0, 3.0])
    
    # Encrypt the data
    encrypted = service.encrypt_embedding(test_data)
    
    # Verify version prefix
    assert encrypted.startswith("v1:")
    
    # Modify version prefix to simulate future version
    future_version = "v2:" + encrypted[3:]
    
    # Should reject unknown version
    with pytest.raises(ValueError):
        service.decrypt_embedding(future_version) 