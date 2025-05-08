"""
Unit tests for the ContactInfo value object.

Tests both the basic functionality and security features for
HIPAA-compliant PHI protection.
"""

import json
import re
from unittest.mock import MagicMock, patch

import pytest

from app.domain.value_objects.contact_info import ContactInfo, create_secure_contact_info
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService,
    encrypt_value,
    decrypt_value,
    get_encryption_service
)


class TestContactInfo:
    """Test suite for ContactInfo value object."""
    
    @pytest.fixture
    def valid_contact_info(self):
        """Create a valid ContactInfo object."""
        return ContactInfo(
            email="test@example.com",
            phone="555-123-4567"
        )
    
    def test_create_valid_contact_info(self):
        """Test creation with valid data."""
        # Arrange & Act
        contact_info = ContactInfo(
            email="test@example.com",
            phone="555-123-4567",
            preferred_contact_method="email"
        )
        
        # Assert
        assert contact_info.email == "test@example.com"
        assert contact_info.phone == "555-123-4567"
        assert contact_info.preferred_contact_method == "email"
        
    def test_create_with_optional_fields(self):
        """Test creation with optional fields."""
        # Arrange & Act
        contact_info = ContactInfo(
            email="test@example.com"
        )
        
        # Assert
        assert contact_info.email == "test@example.com"
        assert contact_info.phone is None
        assert contact_info.preferred_contact_method is None
        
        # Test with only phone
        contact_info = ContactInfo(
            phone="555-123-4567"
        )
        
        # Assert
        assert contact_info.email is None
        assert contact_info.phone == "555-123-4567"
        
    def test_email_validation(self):
        """Test email validation."""
        # Valid email should not raise an error
        ContactInfo(email="test@example.com")
        
        # Invalid email should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            ContactInfo(email="invalid-email")
        assert "Invalid email format" in str(exc_info.value)
        
        # None email should be allowed
        ContactInfo(email=None)
        
        # Non-string email should raise ValueError with safe message
        with pytest.raises(ValueError) as exc_info:
            ContactInfo(email=123)  # type: ignore
        assert "Email must be a string" in str(exc_info.value)
        
    def test_phone_validation(self):
        """Test phone validation."""
        # Valid phone should not raise an error
        ContactInfo(phone="555-123-4567")
        
        # Valid phone with formatting should work
        ContactInfo(phone="(555) 123-4567")
        
        # Invalid phone (too short) should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            ContactInfo(phone="123-456")
        assert "must have at least 10 digits" in str(exc_info.value)
        
        # None phone should be allowed
        ContactInfo(phone=None)
        
        # Non-string phone should raise ValueError with safe message
        with pytest.raises(ValueError) as exc_info:
            ContactInfo(phone=123)  # type: ignore
        assert "Phone number must be a string" in str(exc_info.value)
        
    def test_preferred_contact_method_validation(self):
        """Test preferred contact method validation."""
        # Valid values should not raise an error
        ContactInfo(preferred_contact_method="email")
        ContactInfo(preferred_contact_method="phone")
        ContactInfo(preferred_contact_method="none")
        
        # Case-insensitive check
        ContactInfo(preferred_contact_method="EMAIL")
        
        # Invalid value should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            ContactInfo(preferred_contact_method="invalid")
        assert "Preferred contact method must be one of" in str(exc_info.value)
        
        # None should be allowed
        ContactInfo(preferred_contact_method=None)
        
    def test_to_dict(self, valid_contact_info):
        """Test to_dict method."""
        # Arrange
        expected = {
            "email": "test@example.com",
            "phone": "555-123-4567"
        }
        
        # Act
        result = valid_contact_info.to_dict()
        
        # Assert
        assert result == expected
        
        # Test with preferred contact method
        contact_info_with_pref = ContactInfo(
            email="test@example.com",
            phone="555-123-4567",
            preferred_contact_method="email"
        )
        
        # Act
        result = contact_info_with_pref.to_dict()
        
        # Assert
        assert result["preferred_contact_method"] == "email"
        
        # Test with None values and include_empty=True
        contact_info_with_none = ContactInfo(
            email="test@example.com",
            phone=None
        )
        
        # Act
        result = contact_info_with_none.to_dict(include_empty=True)
        
        # Assert
        assert "phone" in result
        assert result["phone"] is None
        
        # Default behavior should exclude None values
        result = contact_info_with_none.to_dict()
        assert "phone" not in result
        
    def test_to_json(self, valid_contact_info):
        """Test to_json method."""
        # Arrange
        expected_dict = {
            "email": "test@example.com",
            "phone": "555-123-4567"
        }
        
        # Act
        json_str = valid_contact_info.to_json()
        parsed_json = json.loads(json_str)
        
        # Assert
        assert parsed_json == expected_dict
        
    def test_from_dict(self):
        """Test from_dict method."""
        # Arrange
        data = {
            "email": "test@example.com",
            "phone": "555-123-4567",
            "preferred_contact_method": "email"
        }
        
        # Act
        contact_info = ContactInfo.from_dict(data)
        
        # Assert
        assert contact_info.email == "test@example.com"
        assert contact_info.phone == "555-123-4567"
        assert contact_info.preferred_contact_method == "email"
        
        # Test with None data
        contact_info = ContactInfo.from_dict(None)
        assert contact_info.email is None
        assert contact_info.phone is None
        
        # Test with invalid data, should raise sanitized error
        with pytest.raises(ValueError) as exc_info:
            ContactInfo.from_dict({"email": "invalid-email"})
        assert "Invalid contact information format" in str(exc_info.value)
        
    def test_has_phi(self, valid_contact_info):
        """Test has_phi method."""
        # Arrange & Act
        result = valid_contact_info.has_phi()
        
        # Assert
        assert result is True
        
        # Test empty contact info
        empty_contact = ContactInfo()
        assert empty_contact.has_phi() is False
        
        # Test with just email
        email_only = ContactInfo(email="test@example.com")
        assert email_only.has_phi() is True
        
    def test_redact_phi(self, valid_contact_info):
        """Test redact_phi method."""
        # Arrange & Act
        redacted = valid_contact_info.redact_phi()
        
        # Assert
        assert "[REDACTED EMAIL]" in redacted["email"]
        assert "[REDACTED PHONE]" in redacted["phone"]
        
        # Test empty contact info
        empty_contact = ContactInfo()
        redacted = empty_contact.redact_phi()
        assert redacted["email"] is None
        assert redacted["phone"] is None
        
    def test_create_secure_contact_info_factory(self):
        """Test the factory function for creating contact info."""
        # Arrange & Act
        contact_info = create_secure_contact_info(
            email="test@example.com",
            phone="555-123-4567",
            preferred_method="email"
        )
        
        # Assert
        assert contact_info.email == "test@example.com"
        assert contact_info.phone == "555-123-4567"
        assert contact_info.preferred_contact_method == "email"
        
        # Test with invalid data, should raise sanitized error
        with pytest.raises(ValueError) as exc_info:
            create_secure_contact_info(email="invalid-email")
        assert "Invalid contact information" in str(exc_info.value)


@patch('app.infrastructure.security.encryption.base_encryption_service.BaseEncryptionService.encrypt')
@patch('app.infrastructure.security.encryption.base_encryption_service.BaseEncryptionService.decrypt')
class TestContactInfoEncryption:
    """Test suite for ContactInfo encryption capabilities."""
    
    def test_encryption(self, mock_decrypt, mock_encrypt):
        """Test encryption of ContactInfo."""
        # Setup mock
        mock_encrypt.side_effect = lambda val: f"v1:encrypted_{val}"
        
        # Arrange
        contact_info = ContactInfo(
            email="test@example.com",
            phone="555-123-4567"
        )
        
        # Act
        encrypted = contact_info.encrypt()
        
        # Assert
        assert encrypted._is_encrypted is True
        assert encrypted.email == "v1:encrypted_test@example.com"
        assert encrypted.phone == "v1:encrypted_555-123-4567"
        assert encrypted.preferred_contact_method is None
        
        # Verify mock called
        assert mock_encrypt.call_count == 2
        
        # Test with None values
        contact_info = ContactInfo(
            email=None,
            phone=None
        )
        
        # Act
        encrypted = contact_info.encrypt()
        
        # Assert
        assert encrypted._is_encrypted is True
        assert encrypted.email is None
        assert encrypted.phone is None
        assert mock_encrypt.call_count == 2  # No additional calls with None values
        
    def test_decryption(self, mock_decrypt, mock_encrypt):
        """Test decryption of ContactInfo."""
        # Setup mock
        mock_decrypt.side_effect = lambda val: val.replace("v1:encrypted_", "")
        
        # Arrange - create an encrypted instance directly
        contact_info = ContactInfo(
            email="v1:encrypted_test@example.com",
            phone="v1:encrypted_555-123-4567",
            _is_encrypted=True
        )
        
        # Act
        decrypted = contact_info.decrypt()
        
        # Assert
        assert decrypted._is_encrypted is False
        assert decrypted.email == "test@example.com"
        assert decrypted.phone == "555-123-4567"
        
        # Verify mock called
        assert mock_decrypt.call_count == 2
        
        # Test with None values
        contact_info = ContactInfo(
            email=None,
            phone=None,
            _is_encrypted=True
        )
        
        # Act
        decrypted = contact_info.decrypt()
        
        # Assert
        assert decrypted._is_encrypted is False
        assert decrypted.email is None
        assert decrypted.phone is None
        assert mock_decrypt.call_count == 2  # No additional calls with None values
        
        # Test with already decrypted instance
        contact_info = ContactInfo(
            email="test@example.com",
            phone="555-123-4567",
            _is_encrypted=False
        )
        
        # Act
        decrypted = contact_info.decrypt()
        
        # Assert - should return self, no changes
        assert decrypted is contact_info
        assert mock_decrypt.call_count == 2  # No additional calls
        
    def test_detect_encryption_state(self, mock_decrypt, mock_encrypt):
        """Test automatic detection of encryption state."""
        # Arrange - with encrypted values
        contact_info = ContactInfo(
            email="v1:encrypted_test@example.com",
            phone="555-123-4567"
        )
        
        # Assert
        assert contact_info._is_encrypted is True
        
        # Arrange - with plaintext values
        contact_info = ContactInfo(
            email="test@example.com",
            phone="555-123-4567"
        )
        
        # Assert
        assert contact_info._is_encrypted is False
        
    def test_get_encryption_service(self, mock_decrypt, mock_encrypt):
        """Test retrieval of encryption service."""
        # Arrange
        ContactInfo._encryption_service = None  # Clear cache
        
        # Mock the get_encryption_service
        with patch('app.domain.value_objects.contact_info.get_encryption_service') as mock_get_service:
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            
            # Act
            service = ContactInfo._get_encryption_service()
            
            # Assert
            assert service is mock_service
            mock_get_service.assert_called_once()
            
            # Test caching
            service2 = ContactInfo._get_encryption_service()
            assert service2 is mock_service
            assert mock_get_service.call_count == 1  # Still only called once due to caching


class TestContactInfoEndToEnd:
    """Test suite for end-to-end encryption of ContactInfo."""
    
    @pytest.fixture(scope="class")
    def test_encryption_key(self):
        """Provide test encryption key."""
        return "test_encryption_key_for_unit_tests_only_12345"
    
    def test_real_encryption_decryption(self, test_encryption_key):
        """Test real encryption and decryption with actual service."""
        # Skip if no encryption service available
        try:
            # Override settings for test
            with patch('app.core.config.settings.get_settings') as mock_settings:
                # Create a mock settings object
                settings = MagicMock()
                settings.PHI_ENCRYPTION_KEY = test_encryption_key
                mock_settings.return_value = settings
                
                # Clear service cache
                ContactInfo._encryption_service = None
                
                # Arrange
                contact_info = ContactInfo(
                    email="test@example.com",
                    phone="555-123-4567"
                )
                
                # Act: Encrypt
                encrypted = contact_info.encrypt()
                
                # Assert encryption
                assert encrypted._is_encrypted is True
                assert encrypted.email != "test@example.com"
                assert encrypted.email.startswith("v1:")
                assert encrypted.phone != "555-123-4567"
                assert encrypted.phone.startswith("v1:")
                
                # Act: Decrypt back
                decrypted = encrypted.decrypt()
                
                # Assert decryption
                assert decrypted._is_encrypted is False
                assert decrypted.email == "test@example.com"
                assert decrypted.phone == "555-123-4567"
        except (ImportError, ValueError):
            pytest.skip("Encryption service not available in this environment")


# Test integration with other classes using composition
class Patient:
    """Demo class for testing ContactInfo integration."""
    
    def __init__(self, email=None, phone=None):
        """Initialize with ContactInfo."""
        self._contact_info = ContactInfo(
            email=email,
            phone=phone
        )
    
    @property
    def contact_info(self):
        """Get ContactInfo."""
        return self._contact_info
    
    @contact_info.setter
    def contact_info(self, value):
        """Set ContactInfo with type checking."""
        if not isinstance(value, ContactInfo):
            if isinstance(value, dict):
                value = ContactInfo.from_dict(value)
            else:
                raise TypeError("contact_info must be a ContactInfo object")
        self._contact_info = value


# Demonstrate descriptor pattern for ContactInfo (optional advanced usage)
class ContactInfoDescriptor:
    """Descriptor for ContactInfo property."""
    
    def __get__(self, instance, owner):
        """Get contact info."""
        if instance is None:
            return self
        return instance._contact_info
    
    def __set__(self, instance, value):
        """Set contact info with validation and type conversion."""
        if not isinstance(value, ContactInfo):
            if isinstance(value, dict):
                value = ContactInfo.from_dict(value)
            elif isinstance(value, (tuple, list)) and len(value) >= 2:
                value = ContactInfo(email=value[0], phone=value[1])
            else:
                raise TypeError("Expected ContactInfo, dict, or tuple")
        instance._contact_info = value


def test_patient_integration():
    """Test integration with the Patient class."""
    # Create a patient with contact info
    patient = Patient("patient@example.com", "555-987-6543")
    
    # Verify contact info
    assert patient.contact_info.email == "patient@example.com"
    assert patient.contact_info.phone == "555-987-6543"
    
    # Update contact info with new ContactInfo object
    new_contact = ContactInfo(email="new@example.com", phone="555-123-4567")
    patient.contact_info = new_contact
    assert patient.contact_info.email == "new@example.com"
    
    # Update contact info with dict
    patient.contact_info = {"email": "dict@example.com", "phone": "555-111-2222"}
    assert patient.contact_info.email == "dict@example.com"
    assert patient.contact_info.phone == "555-111-2222"
    
    # Should raise error for invalid type
    with pytest.raises(TypeError):
        patient.contact_info = "invalid"
    
    # Test with descriptor
    class PatientWithDescriptor:
        """Patient with descriptor-based contact_info."""
        def __init__(self, email=None, phone=None):
            self.email = email
            self.phone = phone
        
        contact_info = ContactInfoDescriptor()
    
    # Create instance
    patient_desc = PatientWithDescriptor()
    with pytest.raises(AttributeError):
        # contact_info not set yet
        _ = patient_desc.contact_info
    
    # Set initial value
    patient_desc._contact_info = ContactInfo(email="patient@example.com")
    assert patient_desc.contact_info.email == "patient@example.com"
    
    # Update with a dict
    patient_desc.contact_info = {"email": "desc@example.com"}
    assert patient_desc.contact_info.email == "desc@example.com"
    
    # Update with a tuple
    patient_desc.contact_info = ("tuple@example.com", "555-333-4444")
    assert patient_desc.contact_info.email == "tuple@example.com"
    assert patient_desc.contact_info.phone == "555-333-4444"
