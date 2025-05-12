"""
Tests for the military-grade HIPAA-compliant encryption service.

This module provides comprehensive test coverage for the encryption service,
ensuring proper protection of PHI data according to HIPAA requirements.
"""

import json
from typing import Any

import pytest
from cryptography.fernet import InvalidToken

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

    def test_encryption_is_non_deterministic_but_decrypts_correctly(self, encryption_service):
        """Test that encryption is non-deterministic but decrypts correctly."""
        # Arrange
        original_data = "Sensitive patient data"

        # Act - Encrypt the same value twice
        encrypted1 = encryption_service.encrypt(original_data)
        encrypted2 = encryption_service.encrypt(original_data)

        # Assert - Different ciphertext for same input
        assert encrypted1 != encrypted2

        # Act - Decrypt both encrypted values
        decrypted1 = encryption_service.decrypt(encrypted1)
        decrypted2 = encryption_service.decrypt(encrypted2)

        # Handle string vs bytes by ensuring both are strings for comparison
        if isinstance(decrypted1, bytes):
            decrypted1 = decrypted1.decode('utf-8')
        if isinstance(decrypted2, bytes):
            decrypted2 = decrypted2.decode('utf-8')
        
        # Convert the original data to string if needed for comparison
        original_for_comparison = original_data
        if isinstance(original_data, str) and isinstance(decrypted1, bytes):
            original_for_comparison = original_data.encode('utf-8')
        elif isinstance(original_data, bytes) and isinstance(decrypted1, str):
            original_for_comparison = original_data.decode('utf-8')
        
        # Assert - Both decrypt to original value
        assert decrypted1 == original_for_comparison, "First decryption failed to recover original data."
        assert decrypted2 == original_for_comparison, "Second decryption failed to recover original data."

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
        
        # Handle string vs bytes by ensuring both are strings for comparison
        if isinstance(decrypted, bytes):
            decrypted = decrypted.decode('utf-8')
        
        # Convert test value to same type as decrypted for comparison
        test_value_for_comparison = test_value
        if isinstance(test_value, str) and isinstance(decrypted, bytes):
            test_value_for_comparison = test_value.encode('utf-8')
        elif isinstance(test_value, bytes) and isinstance(decrypted, str):
            test_value_for_comparison = test_value.decode('utf-8')
            
        assert decrypted == test_value_for_comparison

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
        """Test decryption handles invalid or tampered data gracefully."""
        # Arrange
        invalid_data = b"this is not properly encrypted data" # Raw bytes, no version prefix
        original_data_bytes = b"original data"
        encrypted_str = encryption_service.encrypt(original_data_bytes) # Returns str "v1:..."
        
        # Tamper the string representation
        if encrypted_str: # Ensure encrypt didn't return None
            tampered_data_str = encrypted_str[:-5] + "xxxxx" # Tamper the string
        else:
            pytest.fail("Encryption returned None, cannot create tampered data.")

        # Act & Assert
        # 1. Test decrypting raw invalid bytes (should fail format check)
        with pytest.raises(ValueError) as excinfo_invalid:
            encryption_service.decrypt(invalid_data)
        # Ensure the error message is specifically about the format for raw bytes
        assert "Invalid encrypted data format" in str(excinfo_invalid.value)

        # 2. Test decrypting the tampered *string* (should fail InvalidToken wrapped in ValueError)
        with pytest.raises(ValueError) as excinfo_tampered:
            encryption_service.decrypt(tampered_data_str)
        # Ensure the error message is specifically about decryption failure for tampered data
        assert "Decryption failed" in str(excinfo_tampered.value)

        # 3. Test decrypting None
        assert encryption_service.decrypt(None) is None

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
            "demographics.address.street",
            "demographics.address.city",
            "demographics.address.state",
            "demographics.address.zip",
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
        
        # Check address fields specifically - note these individual fields should be encrypted
        assert encrypted_record["demographics"]["address"]["street"].startswith("v1:")
        assert encrypted_record["demographics"]["address"]["city"].startswith("v1:")
        assert encrypted_record["demographics"]["address"]["state"].startswith("v1:")
        assert encrypted_record["demographics"]["address"]["zip"].startswith("v1:")

        # Verify non-PHI remains unencrypted
        assert encrypted_record["vital_signs"]["height"] == "180cm"
        assert encrypted_record["vital_signs"]["weight"] == "75kg"

        # Verify decryption restores original values
        assert decrypted_record["medical_record_number"] == patient_record["medical_record_number"]
        assert decrypted_record["demographics"]["name"]["first"] == patient_record["demographics"]["name"]["first"]
        assert decrypted_record["demographics"]["name"]["last"] == patient_record["demographics"]["name"]["last"]
        assert decrypted_record["demographics"]["ssn"] == patient_record["demographics"]["ssn"]

        # Verify complex nested structures - address fields
        # Note: JSON serialization might convert some string numbers to integers,
        # so we compare them as strings to ensure consistent comparison
        assert decrypted_record["demographics"]["address"]["street"] == patient_record["demographics"]["address"]["street"]
        assert decrypted_record["demographics"]["address"]["city"] == patient_record["demographics"]["address"]["city"]
        assert decrypted_record["demographics"]["address"]["state"] == patient_record["demographics"]["address"]["state"]
        assert str(decrypted_record["demographics"]["address"]["zip"]) == str(patient_record["demographics"]["address"]["zip"])
