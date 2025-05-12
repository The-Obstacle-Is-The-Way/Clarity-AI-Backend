"""
Test helper for address handling in field encryption.

This module ensures proper encryption of address data structures
while maintaining HIPAA compliance.
"""

import ast  # Import ast for literal_eval

import pytest

from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from app.infrastructure.security.encryption.field_encryptor import FieldEncryptor
from app.tests.mocks.mock_encryption_service import MockEncryptionService

# TEMP: Comment out missing AddressHelper import
# from app.infrastructure.utils.address_helper import AddressHelper 
# TEMP: Comment out missing Address entity import
# from app.domain.entities.address import Address


def test_address_field_encryption():
    """Test address field encryption"""
    # Create a field encryption service
    encryption_service = BaseEncryptionService(direct_key="test_key_for_address_encryption")
    field_encryptor = FieldEncryptor(encryption_service=encryption_service)

    # Sample data with an address
    data = {
        "patient_id": "12345",
        "name": "John Smith",
        "demographics": {
            "address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip": "12345"
            },
            "date_of_birth": "1980-01-01",
            "ssn": "123-45-6789"
        },
        "diagnosis": "F41.1"
    }

    # Encrypt specific fields
    encrypted_data = field_encryptor.encrypt_fields(data, ["demographics.address.street", 
                                                         "demographics.address.city",
                                                         "demographics.address.state",
                                                         "demographics.address.zip"])

    # Verify the street was encrypted
    assert encrypted_data["demographics"]["address"]["street"].startswith("v1:")
    assert encrypted_data["demographics"]["address"]["city"].startswith("v1:")
    
    # Decrypt the data
    decrypted_data = field_encryptor.decrypt_fields(encrypted_data, ["demographics.address.street", 
                                                                   "demographics.address.city",
                                                                   "demographics.address.state",
                                                                   "demographics.address.zip"])
    
    # Verify decryption worked correctly
    assert decrypted_data["demographics"]["address"]["street"] == "123 Main St"
    assert decrypted_data["demographics"]["address"]["city"] == "Anytown"


if __name__ == "__main__":
    # Indent the code block
    test_address_field_encryption()
    print("Address field encryption test passed!")
