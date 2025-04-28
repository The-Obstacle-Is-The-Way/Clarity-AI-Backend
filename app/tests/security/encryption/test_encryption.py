#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HIPAA Security Test Suite - Encryption Tests

This module tests the field-level encryption functionality for PHI (Protected Health Information)
to ensure compliance with HIPAA requirements for data at rest encryption.

It verifies:
    1. Field-level encryption for PHI attributes
    2. Encryption key management
    3. Data integrity during encryption/decryption
    4. Security of the encryption implementation
"""

import os
import unittest
import pytest
import uuid
from typing import Dict, Any, List, Optional
import json

# Import the encryption modules from infrastructure layer
# Removed empty import block for app.infrastructure.security.encryption

from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from cryptography.fernet import InvalidToken

# Updated import path for MockEncryptionService
# from app.infrastructure.security.encryption.mock_encryption_service import MockEncryptionService # Old incorrect path
from app.tests.security.utils.test_mocks import MockEncryptionService # Correct path

# Correct import for FieldEncryptor
from app.infrastructure.security.encryption.field_encryptor import FieldEncryptor

# Rename test class to reflect FieldEncryptor testing
class TestFieldEncryption(unittest.TestCase):
    """Test suite for FieldEncryptor."""

    def setUp(self):
        """Set up test environment."""
        # Instantiate BaseEncryptionService (using Mock for testing)
        self.encryption_service = MockEncryptionService() 
        self.encryption = FieldEncryptor(self.encryption_service) # Instantiate FieldEncryptor

        # Define PHI fields for testing
        self.phi_fields = [
            "patient_id",
            "name",
            "address",
            "demographics.ssn",
            "demographics.address.street",
            "demographics.address.city",
            "contact_info.email",
        ]

        # Test data with PHI
        self.test_data = {
            "patient_id": "12345",
            "name": "John Smith",
            "gender": "M",  # Not PHI
            "address": "123 Main St, Anytown, USA",
            "diagnosis": "F41.1",  # Not direct PHI
            "demographics": {
                "ssn": "123-45-6789",
                "date_of_birth": "1980-01-01",
                "address": {
                    "street": "123 Main St",
                    "city": "Anytown",
                    "state": "CA",
                    "zip": "12345",
                },
            },
            "contact_info": {
                "email": "john.smith@example.com",
                "phone": "555-123-4567",
            },
        }

    def test_encrypt_decrypt_value(self):
        """Test encryption and decryption of a single value."""
        # Test with a regular string
        original = "This is sensitive PHI data"
        encrypted = self.encryption_service.encrypt(original) # Use service directly

        # Encrypted value should be different from original
        self.assertNotEqual(original, encrypted)

        # Decrypted value should match original
        decrypted = self.encryption_service.decrypt(encrypted) # Use service directly
        self.assertEqual(original, decrypted)

        # Test with None or empty string
        self.assertEqual("", self.encryption_service.encrypt(""))
        self.assertEqual(None, self.encryption_service.encrypt(None))

    def test_encrypt_decrypt_dict(self):
        """Test encryption and decryption of PHI fields in a dictionary."""
        # Make a copy of the original data
        original_data = json.loads(json.dumps(self.test_data))

        # Encrypt the PHI fields using FieldEncryptor
        encrypted_data = self.encryption.encrypt_fields(self.test_data, self.phi_fields)

        # PHI fields should be encrypted
        self.assertNotEqual(original_data["patient_id"], encrypted_data["patient_id"])
        self.assertNotEqual(original_data["name"], encrypted_data["name"])
        self.assertNotEqual(original_data["address"], encrypted_data["address"])
        self.assertNotEqual(original_data["demographics"]["ssn"], encrypted_data["demographics"]["ssn"])

        # Non-PHI fields should remain unchanged
        self.assertEqual(original_data["gender"], encrypted_data["gender"])
        self.assertEqual(original_data["diagnosis"], encrypted_data["diagnosis"])

        # Decrypt the data using FieldEncryptor
        decrypted_data = self.encryption.decrypt_fields(encrypted_data, self.phi_fields)

        # Decrypted data should match original
        self.assertEqual(original_data, decrypted_data)

    def test_nested_field_encryption(self):
        """Test encryption of nested fields."""
        # Make a copy of the original data
        original_data = json.loads(json.dumps(self.test_data))

        # Encrypt the PHI fields using FieldEncryptor
        encrypted_data = self.encryption.encrypt_fields(self.test_data, self.phi_fields)

        # Nested PHI fields should be encrypted
        self.assertNotEqual(original_data["demographics"]["address"]["street"], encrypted_data["demographics"]["address"]["street"])

        # Decrypt the data using FieldEncryptor
        decrypted_data = self.encryption.decrypt_fields(encrypted_data, self.phi_fields)

        # Original and decrypted data should match
        self.assertEqual(original_data["demographics"]["address"]["street"], decrypted_data["demographics"]["address"]["street"])

    def test_multiple_operations(self):
        """Test multiple encryption/decryption operations."""
        data = json.loads(json.dumps(self.test_data))
        original_data = json.loads(json.dumps(self.test_data))

        # Perform multiple encrypt/decrypt operations using FieldEncryptor
        for _ in range(5):
            data = self.encryption.encrypt_fields(data, self.phi_fields)
            data = self.encryption.decrypt_fields(data, self.phi_fields)

        # Data should remain unchanged
        self.assertEqual(original_data, data)

    def test_error_handling(self):
        """Test error handling during encryption/decryption."""
        # Test handling of invalid encrypted data
        invalid_encrypted = "ENC_INVALID"  # Missing proper format

        try:
            result = self.encryption_service.decrypt(invalid_encrypted) # Use service directly
            # If no exception is raised, the function should return the original value
            self.assertEqual(invalid_encrypted, result)
        except EncryptionError:
            # If an exception is raised, that's also acceptable
            pass

    def test_hipaa_compliance(self):
        """Verify compliance with HIPAA requirements."""
        # Generate some test data
        test_data = {
            "medical_record_number": "MRN12345",
            "diagnosis_code": "F41.1",
            "treatment_notes": "Patient exhibits symptoms of anxiety and depression.",
        }

        # Encrypt the data using FieldEncryptor
        encrypted_data = self.encryption.encrypt_fields(test_data, ["medical_record_number", "treatment_notes"])

        # HIPAA requires that PHI is not visible in storage
        self.assertNotEqual(test_data["medical_record_number"], encrypted_data["medical_record_number"])
        self.assertNotEqual(test_data["treatment_notes"], encrypted_data["treatment_notes"])

        # Diagnosis code (not considered direct PHI) should remain unchanged
        self.assertEqual(test_data["diagnosis_code"], encrypted_data["diagnosis_code"])

        # Verify data can be correctly decrypted using FieldEncryptor
        decrypted_data = self.encryption.decrypt_fields(encrypted_data, ["medical_record_number", "treatment_notes"])
        
        self.assertEqual(test_data, decrypted_data)


# Run the tests if the script is executed directly
if __name__ == "__main__":
    unittest.main()
