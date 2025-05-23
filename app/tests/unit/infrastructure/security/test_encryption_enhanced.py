"""
Enhanced unit tests for the encryption utility.

This test suite provides comprehensive coverage for the encryption module,
ensuring secure data handling and HIPAA-compliant data protection.
"""


import pytest
from cryptography.fernet import Fernet

# Correctly import the necessary components
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService,
)

# Define constants for testing
TEST_KEY_MATERIAL = "test-key-material-needs-32-bytes!"
TEST_SALT = b"test-salt-16-bytes"
TEST_DATA = "This is sensitive test data."


@pytest.mark.unit()
class TestEncryptionUtils:
    """Tests for the encryption utility functions."""

    # TODO: Refactor tests for derive_key as the function is not public.
    #       Test the behavior of _get_key() indirectly via service initialization.
    # @pytest.mark.parametrize(
    #     "password, salt, expected_key_length",
    #     [
    #         ("testpassword", TEST_SALT, 32),
    #         ("another-secure-password-123", os.urandom(16), 32),
    #     ]
    # )
    # def test_derive_key(password, salt, expected_key_length):
    #     """Test key derivation produces a key of the correct length."""
    #     derived = derive_key(password.encode(), salt)
    #     assert isinstance(derived, bytes)
    #     assert len(base64.urlsafe_b64decode(derived)) == expected_key_length

    # def test_derive_key_with_invalid_input():
    #     """Test key derivation with invalid input types."""
    #     with pytest.raises(TypeError):
    #         derive_key(12345, TEST_SALT) # Non-bytes password
    #     with pytest.raises(TypeError):
    #         derive_key(b"password", "not_bytes_salt") # Non-bytes salt

    # def test_derive_key_determinism():
    #     """Test that key derivation is deterministic."""
    #     key1 = derive_key(b"password", TEST_SALT)
    #     key2 = derive_key(b"password", TEST_SALT)
    #     assert key1 == key2

    def test_encrypt_decrypt_cycle(self, encryption_service) -> None:
        """Test that encrypting and then decrypting returns the original data."""
        encrypted = encryption_service.encrypt(TEST_DATA)  # Use service method
        assert encrypted != TEST_DATA
        assert isinstance(encrypted, str)
        assert encrypted.startswith(BaseEncryptionService.VERSION_PREFIX)

        decrypted = encryption_service.decrypt(encrypted)  # Use service method
        assert decrypted == TEST_DATA

    def test_decrypt_invalid_token(self, encryption_service) -> None:
        """Test decryption with an invalid token raises ValueError."""
        invalid_encrypted_data = "v1:this-is-not-valid-base64-or-fernet-token"
        with pytest.raises(ValueError):
            encryption_service.decrypt(invalid_encrypted_data)  # Use service method

    # TODO: Locate or reimplement hash_data and secure_compare functionality.
    #       These tests are currently commented out.
    # def test_hash_data_consistency():
    #     """Test that hashing the same data yields the same hash."""
    #     hash1 = hash_data(TEST_DATA)
    #     hash2 = hash_data(TEST_DATA)
    #     assert hash1 == hash2
    #     assert isinstance(hash1, str)

    # def test_hash_data_uniqueness():
    #     """Test that hashing different data yields different hashes."""
    #     hash1 = hash_data(TEST_DATA)
    #     hash2 = hash_data("Slightly different test data.")
    #     assert hash1 != hash2

    # def test_secure_compare_matching():
    #     """Test secure comparison with matching values."""
    #     value = "some_secret_value"
    #     hashed_value = hash_data(value)
    #     assert secure_compare(value, hashed_value)

    # def test_secure_compare_non_matching():
    #     """Test secure comparison with non-matching values."""
    #     value = "some_secret_value"
    #     hashed_value = hash_data("different_value")
    #     assert not secure_compare(value, hashed_value)


@pytest.fixture(scope="module")
def encryption_service() -> BaseEncryptionService:
    """Provide a BaseEncryptionService instance with default test keys."""
    # Use sufficiently long keys for testing
    test_key = "test_encryption_key_longer_than_32_chars"
    test_prev_key = "previous_test_key_also_longer_than_32"
    return BaseEncryptionService(direct_key=test_key, previous_key=test_prev_key)


@pytest.mark.unit()
class TestEnhancedEncryptionService:
    """Tests for the EncryptionService class."""

    def test_initialization(self, encryption_service: BaseEncryptionService) -> None:
        """Test initialization of EncryptionService."""
        # Verify the service is initialized
        assert encryption_service is not None
        assert encryption_service.cipher is not None
        assert isinstance(encryption_service.cipher, Fernet)  # Check type

    def test_encrypt_decrypt(self, encryption_service: BaseEncryptionService) -> None:
        """Test encryption and decryption of data."""
        # Test data
        data = "Sensitive patient information"

        # Encrypt the data
        encrypted = encryption_service.encrypt(data)

        # Verify encrypted data is different from original
        assert encrypted != data
        assert isinstance(encrypted, str)  # Assuming encrypt returns string
        assert encrypted.startswith("v1:")  # Check for version prefix

        # Decrypt the data
        decrypted = encryption_service.decrypt(encrypted)

        # Verify decrypted data matches original
        assert decrypted == data

    def test_encrypt_decrypt_dict(self, encryption_service: BaseEncryptionService) -> None:
        """Test encryption and decryption of dictionaries."""
        # Test data
        data = {
            "patient_id": "12345",
            "name": "John Smith",
            "diagnosis": "F41.1",  # Non-sensitive example
            "ssn": "123-45-6789",
            "address": {
                "street": "123 Main St",
                "city": "Anytown",  # Non-sensitive example
                "state": "CA",  # Non-sensitive example
                "zip": "12345",  # Non-sensitive example
            },
            "medications": [  # Example of list handling
                {"name": "Med1", "dosage": "10mg"},
                {"name": "Med2", "dosage": "20mg"},
            ],
            "notes": None,  # Test None value
            "age": 42,  # Test integer value
        }

        # Encrypt the data (assuming encrypt_dict handles structure)
        encrypted = encryption_service.encrypt_dict(data)

        # Verify sensitive fields are encrypted (check format)
        assert isinstance(encrypted["patient_id"], str) and encrypted["patient_id"].startswith(
            "v1:"
        )
        assert isinstance(encrypted["name"], str) and encrypted["name"].startswith("v1:")
        assert isinstance(encrypted["ssn"], str) and encrypted["ssn"].startswith("v1:")
        assert isinstance(
            encrypted["address"], dict
        )  # Address itself isn't encrypted, only fields within
        assert isinstance(encrypted["address"]["street"], str) and encrypted["address"][
            "street"
        ].startswith("v1:")

        # Non-sensitive fields should remain unchanged
        assert encrypted["diagnosis"] == data["diagnosis"]
        assert encrypted["address"]["city"] == data["address"]["city"]
        assert encrypted["address"]["state"] == data["address"]["state"]
        assert encrypted["address"]["zip"] == data["address"]["zip"]
        assert encrypted["age"] == data["age"]
        assert encrypted["notes"] is None  # None values should be preserved

        # Verify list structure and encrypted content within lists
        assert isinstance(encrypted["medications"], list)
        assert len(encrypted["medications"]) == 2
        assert isinstance(encrypted["medications"][0], dict)
        assert isinstance(encrypted["medications"][0]["name"], str) and encrypted["medications"][0][
            "name"
        ].startswith("v1:")
        assert isinstance(encrypted["medications"][0]["dosage"], str) and encrypted["medications"][
            0
        ]["dosage"].startswith("v1:")

        # Decrypt the data
        decrypted = encryption_service.decrypt_dict(encrypted)

        # Verify decrypted data matches original (deep comparison might be needed)
        assert decrypted == data  # Simple comparison works if structure and values match

    def test_key_rotation(self) -> None:
        """Test encryption key rotation using fixed test keys."""
        # Use fixed test keys and salt for reliable testing
        primary_key = "test_primary_key_for_rotation_testing_1"
        previous_key = "test_previous_key_for_rotation_testing_2"
        test_salt = b"salt-for-testing-rotation-key-12345"
        test_data = "Sensitive PHI data for rotation test"

        # Create service with only the previous key
        service_prev = BaseEncryptionService(direct_key=previous_key, salt=test_salt)

        # Encrypt data with previous key
        encrypted_with_prev = service_prev.encrypt(test_data)
        assert encrypted_with_prev.startswith("v1:")

        # Create a new service with a new primary key and the previous key
        service_new = BaseEncryptionService(
            direct_key=primary_key, previous_key=previous_key, salt=test_salt
        )

        # Service should be able to decrypt data encrypted with previous key
        decrypted = service_new.decrypt(encrypted_with_prev)
        assert decrypted == test_data

        # Encrypt with new primary key
        encrypted_with_new = service_new.encrypt(test_data)
        assert encrypted_with_new != encrypted_with_prev

        # Verify new encryption works
        assert service_new.decrypt(encrypted_with_new) == test_data

        # Verify previous service can't decrypt data encrypted with new key
        with pytest.raises(ValueError, match="Decryption failed: Invalid token"):
            service_prev.decrypt(encrypted_with_new)

    def test_file_encryption(self, encryption_service: BaseEncryptionService, tmp_path) -> None:
        """Test encryption and decryption of files."""
        # Create test file paths
        test_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "encrypted.bin"
        decrypted_file = tmp_path / "decrypted.txt"

        # Test content
        test_content = "Sensitive patient information\nLine 2\nLine3"
        test_file.write_text(test_content)

        # Encrypt the file
        encryption_service.encrypt_file(str(test_file), str(encrypted_file))

        # Verify encrypted file exists and is different
        assert encrypted_file.exists()
        assert encrypted_file.read_bytes() != test_content.encode()

        # Decrypt the file
        encryption_service.decrypt_file(str(encrypted_file), str(decrypted_file))

        # Verify decrypted content matches original
        assert decrypted_file.exists()
        assert decrypted_file.read_text() == test_content

    def test_encrypt_file_nonexistent(self, encryption_service: BaseEncryptionService, tmp_path) -> None:
        """Test encrypting a nonexistent file raises FileNotFoundError."""
        nonexistent_file = tmp_path / "nonexistent.txt"
        output_file = tmp_path / "output.bin"

        # Attempt to encrypt a nonexistent file
        with pytest.raises(FileNotFoundError):
            encryption_service.encrypt_file(str(nonexistent_file), str(output_file))

    def test_decrypt_file_nonexistent(self, encryption_service: BaseEncryptionService, tmp_path) -> None:
        """Test decrypting a nonexistent file raises FileNotFoundError."""
        nonexistent_file = tmp_path / "nonexistent.bin"
        output_file = tmp_path / "output.txt"

        # Attempt to decrypt a nonexistent file
        with pytest.raises(FileNotFoundError):
            encryption_service.decrypt_file(str(nonexistent_file), str(output_file))

    def test_decrypt_invalid_file_content(
        self, encryption_service: BaseEncryptionService, tmp_path
    ) -> None:
        """Test decrypting a file with invalid content raises ValueError."""
        invalid_encrypted_file = tmp_path / "invalid.bin"
        output_file = tmp_path / "output.txt"

        # Create a file with invalid content
        invalid_encrypted_file.write_bytes(b"This is not a valid Fernet token")

        # Attempt to decrypt an invalid file
        with pytest.raises(ValueError, match=r"Decryption failed for file.*invalid token"):
            encryption_service.decrypt_file(str(invalid_encrypted_file), str(output_file))
