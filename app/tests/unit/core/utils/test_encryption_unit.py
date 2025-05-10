"""
Unit tests for the HIPAA-compliant encryption utility.
"""

import os
from unittest.mock import patch

import pytest

from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService as EncryptionService,
)


@pytest.mark.venv_only()
class TestEncryptionService:
    """Tests for the HIPAA-compliant encryption service."""
    
    @pytest.fixture
    def encryption_service(self):
        """Create an encryption service with a test key."""
        with patch.dict(os.environ, {"ENCRYPTION_KEY": "test_secret_key_for_encryption_service_tests"}):
            return EncryptionService()

    def test_initialization(self):
        """Test encryption service initialization."""
        with patch.dict(os.environ, {"ENCRYPTION_KEY": "test_key_for_encryption_abracadabra"}):
            service = EncryptionService()
            assert service.cipher is not None

    def test_initialization_with_missing_key(self):
        """Test initialization with missing key raises error."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as excinfo:
                EncryptionService()
            assert "Encryption key not provided" in str(excinfo.value)

    def test_encrypt_decrypt_string(self, encryption_service):
        """Test encrypting and decrypting a string using encrypt_string/decrypt_string."""
        plaintext = "This is sensitive patient information"

        # Encrypt the string
        encrypted = encryption_service.encrypt_string(plaintext)

        # Verify the encrypted text is different from plaintext
        assert encrypted != plaintext
        assert isinstance(encrypted, str) # Ensure it returns string

        # Decrypt the string
        decrypted = encryption_service.decrypt_string(encrypted)

        # Verify the decrypted text matches the original
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_string(self, encryption_service):
        """Test encrypting and decrypting an empty string using encrypt_string/decrypt_string."""
        plaintext = ""

        # Encrypt the string
        encrypted = encryption_service.encrypt_string(plaintext)

        # For Fernet, empty string encryption results in a non-empty encrypted string.
        # If the requirement is for empty string to remain empty, BaseEncryptionService needs adjustment.
        # Current BaseEncryptionService with Fernet will not return empty for empty.
        # Let's assert it's not the original plaintext and is a string.
        assert encrypted != plaintext 
        assert isinstance(encrypted, str)
        
        # If it encrypts to non-empty, it should decrypt back to empty.
        decrypted = encryption_service.decrypt_string(encrypted)
        assert decrypted == plaintext # Should decrypt back to empty string

    def test_decrypt_invalid_string(self, encryption_service):
        """Test decrypting an invalid string with decrypt_string raises error."""
        with pytest.raises(ValueError) as excinfo:
            # Using a string that is not valid Fernet token
            encryption_service.decrypt_string("invalid_fernet_token_string") 
        assert "Failed to decrypt" in str(excinfo.value)

    def test_generate_verify_hash(self, encryption_service):
        """Test generating and verifying a hash."""
        data = "sensitive_data"

        # Generate hash
        hash_value, salt = encryption_service.generate_hash(data)

        # Verify hash is a string and salt is string (hex-encoded)
        assert isinstance(hash_value, str)
        assert isinstance(salt, str) # Changed from bytes to str

        # Verify the hash
        # The verify_hash method in BaseEncryptionService now expects salt_hex (str)
        is_valid = encryption_service.verify_hash(data, salt, hash_value) # salt is already salt_hex
        assert is_valid is True

        # Verify with incorrect data
        is_valid = encryption_service.verify_hash(
            "wrong_data", salt, hash_value # salt is already salt_hex
        )
        assert is_valid is False

    def test_generate_verify_hmac(self, encryption_service):
        """Test generating and verifying an HMAC."""
        data = "data_to_verify_integrity"

        # Generate HMAC
        hmac_value = encryption_service.generate_hmac(data)

        # Verify HMAC is a string
        assert isinstance(hmac_value, str)

        # Verify the HMAC
        is_valid = encryption_service.verify_hmac(data, hmac_value)
        assert is_valid is True

        # Verify with incorrect data
        is_valid = encryption_service.verify_hmac("wrong_data", hmac_value)
        assert is_valid is False
