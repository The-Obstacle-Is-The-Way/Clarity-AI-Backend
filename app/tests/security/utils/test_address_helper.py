"""
Test helper for address handling in field encryption.

This module ensures proper encryption of address data structures
while maintaining HIPAA compliance.
"""

import ast  # Import ast for literal_eval

import pytest

from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from app.infrastructure.security.encryption.field_encryptor import FieldEncryptor

# TEMP: Comment out missing AddressHelper import
# from app.infrastructure.utils.address_helper import AddressHelper 
# TEMP: Comment out missing Address entity import
# from app.domain.entities.address import Address


def test_address_field_encryption():
    """Test address field handling in the field encryptor."""
    # Setup
    encryption_service = BaseEncryptionService(direct_key="test_address",)
    field_encryptor= FieldEncryptor(encryption_service)

    # Sample nested address dictionary
    original_address = {
        "street": "123 Main St",
        "city": "Anytown",
        "state": "CA",
        "zip": "12345",
    }
    data = {
        "demographics": {
            "address": original_address
        }
    }

    # Encrypt the address field (which contains the dictionary)
    encrypted_data = field_encryptor.encrypt_fields(data, ["demographics.address"])

    # Verify the address field itself is now an encrypted string
    encrypted_address_str = encrypted_data["demographics"]["address"]
    assert isinstance(encrypted_address_str, str)
    assert encrypted_address_str.startswith("v1:") # Check for encryption prefix
    # Ensure the original dictionary is not present directly
    assert encrypted_data["demographics"]["address"] != original_address

    # Decrypt the address field
    decrypted_data = field_encryptor.decrypt_fields(
        encrypted_data, ["demographics.address"]
    )

    # Verify the decrypted address field matches the original dictionary
    # Decrypt_fields seems to return a string representation of the dict
    decrypted_address_str = decrypted_data["demographics"]["address"]
    assert isinstance(decrypted_address_str, str)

    # Use ast.literal_eval to parse the string representation
    try:
        parsed_address = ast.literal_eval(decrypted_address_str)
        assert isinstance(parsed_address, dict)
        assert parsed_address == original_address
    except (ValueError, SyntaxError) as e:
        pytest.fail(f"Failed to parse decrypted string with ast.literal_eval: {e}\nString was: {decrypted_address_str}")


if __name__ == "__main__":
    # Indent the code block
    test_address_field_encryption()
    print("Address field encryption test passed!")
