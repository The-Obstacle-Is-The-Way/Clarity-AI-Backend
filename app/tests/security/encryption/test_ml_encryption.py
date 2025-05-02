"""
Tests for the military-grade HIPAA-compliant encryption service.

This module provides comprehensive test coverage for the encryption service,
ensuring proper protection of PHI data according to HIPAA requirements.
"""

import json
from typing import Any

import pytest

from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from app.infrastructure.security.encryption.field_encryptor import FieldEncryptor


@pytest.fixture
def sensitive_data() -> dict[str, Any]:
    """Test fixture with sensitive PHI data."""
    result = {
        "patient_id": "12345",
        "name": "John Smith",
        "ssn": "123-45-6789",
        "address": "123 Main St, Anytown, USA",
        "date_of_birth": "1980-01-01",
        "diagnosis": "F41.1",
        "medication": "Sertraline 50mg",
        "notes": "Patient reports improved mood following therapy sessions.",
    }
    return result


@pytest.fixture
def encryption_service() -> BaseEncryptionService:
    """Test fixture for encryption service with test key."""
    result = BaseEncryptionService(direct_key="test_key_for_unit_tests_only_12345678")
    return result


@pytest.fixture
def field_encryptor(encryption_service) -> FieldEncryptor:
    """Test fixture for field encryption with test encryption service."""
    result = FieldEncryptor(encryption_service)
    return result


@pytest.fixture
def patient_record() -> dict[str, Any]:
    """Test fixture for a complete patient record with PHI."""
    result = {
        "medical_record_number": "MRN12345",
        "demographics": {
            "name": {
                "first": "John",
                "last": "Doe",
            },
            "date_of_birth": "1980-05-15",
            "ssn": "123-45-6789",
            "address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip": "90210",
            },
            "contact": {"phone": "555-123-4567", "email": "john.doe@example.com"},
            "gender": "Male",
            "race": "White",
            "ethnicity": "Non-Hispanic",
        },
        "visit_reason": "Follow-up for anxiety management",
        "vital_signs": {
            "height": "180cm",
            "weight": "75kg",
            "blood_pressure": "120/80",
            "pulse": 70,
            "temperature": 36.6,
        },
        "medications": [
            {
                "name": "Sertraline",
                "dosage": "50mg",
                "frequency": "Daily",
                "route": "Oral",
            }
        ],
        "allergies": [
            {"substance": "Penicillin", "reaction": "Hives", "severity": "Moderate"}
        ],
        "insurance": {
            "provider": "Blue Cross Blue Shield",
            "policy_number": "BCB123456789",
            "group_number": "654",
        },
    }
    return result


class TestEncryptionService:
    """Test suite for the HIPAA-compliant encryption service."""

    def test_encrypt_decrypt_data(self, encryption_service, sensitive_data):
        """Test basic encryption and decryption of sensitive data."""
        # Arrange
        data_json = json.dumps(sensitive_data)

        # Act
        encrypted = encryption_service.encrypt(data_json)
        decrypted = encryption_service.decrypt(encrypted)

        # Assert
        assert encrypted.startswith("v1:")
        assert encrypted != data_json
        assert json.loads(decrypted) == sensitive_data

    def test_encryption_is_deterministic(self, encryption_service):
        """Test that encryption produces consistent output for testing."""
        # Arrange & Act - Encrypt the same value twice
        value = "test-deterministic-value"
        encrypted1 = encryption_service.encrypt(value)
        encrypted2 = encryption_service.encrypt(value)

        # Assert - With test keys, should be deterministic
        assert encrypted1 == encrypted2

    def test_different_keys(self):
        """Test that different encryption keys produce different outputs."""
        # Create two services with different keys using direct key injection
        service1 = BaseEncryptionService(direct_key="test_key_for_unit_tests_only_12345678")
        service2 = BaseEncryptionService(direct_key="different_test_key_for_unit_tests_456")

        # Create test data
        test_value = "HIPAA_PHI_TEST_DATA_123"

        # Act - Encrypt with service1
        encrypted_by_service1 = service1.encrypt(test_value)

        # Verify service1 can decrypt its own data
        decrypted = service1.decrypt(encrypted_by_service1)
        assert decrypted == test_value

        # Service2 should not be able to decrypt service1's data
        with pytest.raises(ValueError):
            service2.decrypt(encrypted_by_service1)

    def test_detect_tampering(self, encryption_service):
        """Test that tampering with encrypted data is detected."""
        # Arrange
        original = "This is sensitive PHI data!"
        encrypted = encryption_service.encrypt(original)

        # Act - Tamper with the encrypted value by adding an X to the content
        tampered = encrypted[:10] + "X" + encrypted[10:]

        # Assert - Should detect tampering and raise ValueError
        with pytest.raises(ValueError):
            encryption_service.decrypt(tampered)

    def test_handle_invalid_input(self, encryption_service):
        """Test handling of invalid input for encryption/decryption."""
        # Test with None
        with pytest.raises(Exception):
            encryption_service.encrypt(None)

        with pytest.raises(ValueError):
            encryption_service.decrypt(None)

        # Test with empty string for decryption
        with pytest.raises(ValueError):
            encryption_service.decrypt("")

        # Test with non-string for encryption
        with pytest.raises(Exception):
            encryption_service.encrypt(123)

        # Test with invalid format for decryption
        with pytest.raises(ValueError):
            encryption_service.decrypt("not-encrypted")

    def test_key_rotation(self, sensitive_data):
        """Test that key rotation works properly."""
        # Arrange - Create service with current and previous keys
        service_old = BaseEncryptionService(direct_key="rotation_old_key_12345678901234567890")
        service_new = BaseEncryptionService(
            direct_key="rotation_new_key_12345678901234567890",
            previous_key="rotation_old_key_12345678901234567890",
        )

        # Act - Encrypt with old key
        data_json = json.dumps(sensitive_data)
        encrypted_old = service_old.encrypt(data_json)

        # Assert - New service can decrypt data encrypted with old key
        decrypted_old = service_new.decrypt(encrypted_old)
        assert json.loads(decrypted_old) == sensitive_data

        # Act - Encrypt with new key
        encrypted_new = service_new.encrypt(data_json)

        # Assert - New service can decrypt data encrypted with new key
        decrypted_new = service_new.decrypt(encrypted_new)
        assert json.loads(decrypted_new) == sensitive_data


class TestFieldEncryption:
    """Test suite for field-level encryption of PHI data."""

    def test_encrypt_decrypt_fields(self, field_encryptor, patient_record):
        """Test selective field encryption and decryption for PHI data."""
        # Define PHI fields that need encryption according to HIPAA
        phi_fields = [
            "medical_record_number",
            "demographics.name.first",
            "demographics.name.last",
            "demographics.date_of_birth",
            "demographics.ssn",
            "demographics.address",
            "demographics.contact.phone",
            "demographics.contact.email",
            "demographics.race",
            "demographics.ethnicity",
            "visit_reason",
            "medications",
            "allergies",
            "insurance",
        ]

        # Act
        encrypted_record = field_encryptor.encrypt_fields(patient_record, phi_fields)
        decrypted_record = field_encryptor.decrypt_fields(encrypted_record, phi_fields)

        # Assert - All PHI should be encrypted, non-PHI should remain clear
        # Verify PHI is encrypted
        assert encrypted_record["medical_record_number"].startswith("v1:")
        assert encrypted_record["demographics"]["name"]["first"].startswith("v1:")
        assert encrypted_record["demographics"]["name"]["last"].startswith("v1:")
        assert encrypted_record["demographics"]["ssn"].startswith("v1:")
        assert isinstance(encrypted_record["demographics"]["address"], str)
        assert encrypted_record["demographics"]["address"].startswith("v1:")

        # Verify non-PHI remains unencrypted
        assert encrypted_record["vital_signs"]["height"] == "180cm"
        assert encrypted_record["vital_signs"]["weight"] == "75kg"

        # Verify decryption restores original values
        assert decrypted_record["medical_record_number"] == patient_record["medical_record_number"]
        assert decrypted_record["demographics"]["name"]["first"] == patient_record["demographics"]["name"]["first"]
        assert decrypted_record["demographics"]["name"]["last"] == patient_record["demographics"]["name"]["last"]
        assert decrypted_record["demographics"]["ssn"] == patient_record["demographics"]["ssn"]

        # Verify complex nested structures
        if isinstance(patient_record["demographics"]["address"], dict):
            # Address is a dictionary
            assert decrypted_record["demographics"]["address"]["street"] == patient_record["demographics"]["address"]["street"]
            assert decrypted_record["demographics"]["address"]["city"] == patient_record["demographics"]["address"]["city"]
        else:
            # Address is a string or other type
            assert decrypted_record["demographics"]["address"] == patient_record["demographics"]["address"]
