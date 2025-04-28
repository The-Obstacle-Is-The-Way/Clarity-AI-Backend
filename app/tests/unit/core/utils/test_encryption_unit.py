# -*- coding: utf-8 -*-
"""
Unit tests for the HIPAA-compliant encryption utility.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService as EncryptionService


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
        with patch.dict(os.environ, {"ENCRYPTION_KEY": "test_key"}):
            service = EncryptionService()
            assert service.secret_key == "test_key"
            assert service.salt is not None
            assert service.key is not None
            assert service.cipher is not None

    def test_initialization_with_missing_key(self):
        """Test initialization with missing key raises error."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as excinfo:
                EncryptionService()
            assert "Encryption key not provided" in str(excinfo.value)

    def test_encrypt_decrypt_string(self, encryption_service):
        """Test encrypting and decrypting a string."""
        plaintext = "This is sensitive patient information"

        # Encrypt the string
        encrypted = encryption_service.encrypt_string(plaintext)

        # Verify the encrypted text is different from plaintext
        assert encrypted != plaintext

        # Decrypt the string
        decrypted = encryption_service.decrypt_string(encrypted)

        # Verify the decrypted text matches the original
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_string(self, encryption_service):
        """Test encrypting and decrypting an empty string."""
        plaintext = ""

        # Encrypt the string
        encrypted = encryption_service.encrypt_string(plaintext)

        # Verify the encrypted text is also empty
        assert encrypted == ""

        # Decrypt the string
        decrypted = encryption_service.decrypt_string(encrypted)

        # Verify the decrypted text is empty
        assert decrypted == ""

    def test_decrypt_invalid_string(self, encryption_service):
        """Test decrypting an invalid string raises error."""
        with pytest.raises(ValueError) as excinfo:
            encryption_service.decrypt_string("invalid_encrypted_text")
        assert "Failed to decrypt string" in str(excinfo.value)

    def test_encrypt_decrypt_dict(self, encryption_service):
        """Test encrypting and decrypting a dictionary."""
        data = {
            "patient_id": "12345",
            "name": "John Doe",
            "ssn": "123-45-6789",
            "email": "john.doe@example.com",
            "age": 45,
            "is_active": True,
            "notes": "Patient has a history of...",
            "medications": ["med1", "med2"]
        }

        # Encrypt sensitive fields
        sensitive_fields = ["ssn", "email", "notes"]
        encrypted_data = encryption_service.encrypt_dict(data, sensitive_fields)

        # Verify sensitive fields are encrypted
        assert encrypted_data["ssn"] != data["ssn"]
        assert encrypted_data["email"] != data["email"]
        assert encrypted_data["notes"] != data["notes"]

        # Verify non-sensitive fields are not encrypted
        assert encrypted_data["patient_id"] == data["patient_id"]
        assert encrypted_data["name"] == data["name"]
        assert encrypted_data["age"] == data["age"]
        assert encrypted_data["is_active"] == data["is_active"]
        assert encrypted_data["medications"] == data["medications"]

        # Decrypt the data
        decrypted_data = encryption_service.decrypt_dict(
            encrypted_data, sensitive_fields
        )

        # Verify all fields match the original
        assert decrypted_data == data

    def test_encrypt_decrypt_nested_dict(self, encryption_service):
        """Test encrypting and decrypting a nested dictionary."""
        data = {
            "patient": {
                "id": "12345",
                "name": "John Doe",
                "contact": {
                    "email": "john.doe@example.com",
                    "phone": "555-123-4567"
                }
            },
            "medical_info": {
                "diagnosis": "Example diagnosis",
                "ssn": "123-45-6789"
            }
        }

        # Encrypt sensitive fields
        sensitive_fields = ["email", "phone", "ssn"]
        encrypted_data = encryption_service.encrypt_dict(data, sensitive_fields)

        # Verify sensitive fields are encrypted
        assert encrypted_data["patient"]["contact"]["email"] != data["patient"]["contact"]["email"]
        assert encrypted_data["patient"]["contact"]["phone"] != data["patient"]["contact"]["phone"]
        assert encrypted_data["medical_info"]["ssn"] != data["medical_info"]["ssn"]

        # Verify non-sensitive fields are not encrypted
        assert encrypted_data["patient"]["id"] == data["patient"]["id"]
        assert encrypted_data["patient"]["name"] == data["patient"]["name"]
        assert encrypted_data["medical_info"]["diagnosis"] == data["medical_info"]["diagnosis"]

        # Decrypt the data
        decrypted_data = encryption_service.decrypt_dict(
            encrypted_data, sensitive_fields
        )

        # Verify all fields match the original
        assert decrypted_data == data

    def test_generate_verify_hash(self, encryption_service):
        """Test generating and verifying a hash."""
        data = "sensitive_data"

        # Generate hash
        hash_value, salt = encryption_service.generate_hash(data)

        # Verify hash is a string and salt is bytes
        assert isinstance(hash_value, str)
        assert isinstance(salt, bytes)

        # Verify the hash
        is_valid = encryption_service.verify_hash(data, hash_value, salt)
        assert is_valid is True

        # Verify with incorrect data
        is_valid = encryption_service.verify_hash(
            "wrong_data", hash_value, salt
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
