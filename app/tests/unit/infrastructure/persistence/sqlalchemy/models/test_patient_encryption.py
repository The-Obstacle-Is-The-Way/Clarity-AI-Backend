"""Unit tests for Patient SQLAlchemy model encryption via TypeDecorators.

This module tests that the TypeDecorators (EncryptedString, EncryptedText, EncryptedJSON)
used on the PatientModel correctly interact with the EncryptionService.
"""
import base64
import json
import logging
import uuid # Added import for uuid
from unittest.mock import patch, MagicMock, AsyncMock # Added AsyncMock
from datetime import date # Added date

import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

from app.infrastructure.persistence.sqlalchemy.models.patient import Patient as PatientModel
from app.infrastructure.persistence.sqlalchemy.types.encrypted_types import EncryptedString, EncryptedText, EncryptedJSON
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from app.core.domain.entities.patient import Patient as DomainPatient # For from_domain/to_domain tests
from app.core.domain.enums import Gender # Corrected import for Gender

logger = logging.getLogger(__name__)

@pytest.fixture
def mock_encryption_service_for_model_tests() -> MagicMock:
    """Provides a mock encryption service for model/TypeDecorator tests."""
    mock_service = MagicMock(spec=BaseEncryptionService)

    # Mock implementation of encrypt
    def mock_encrypt(data: bytes) -> bytes:
        if data is None:
            return None
        if isinstance(data, str):
            data = data.encode('utf-8')
        return f"encrypted_{data.decode('utf-8')}".encode('utf-8')
        
    # Mock implementation of decrypt
    def mock_decrypt(encrypted_data: bytes) -> bytes:
        if encrypted_data is None:
            return None
        if isinstance(encrypted_data, str):
            encrypted_str = encrypted_data
        else:
            encrypted_str = encrypted_data.decode('utf-8')
            
        if encrypted_str.startswith("encrypted_"):
            return encrypted_str[len("encrypted_"):].encode('utf-8')
        
        # Remove version prefix if present
        if encrypted_str.startswith("v1:"):
            encrypted_str = encrypted_str[3:]
            
        if encrypted_str.startswith("encrypted_"):
            return encrypted_str[len("encrypted_"):].encode('utf-8')
            
        return encrypted_str.encode('utf-8')
    
    # Mock implementation of encrypt_string
    def mock_encrypt_string(data: str) -> str:
        if data is None:
            return None
        return f"encrypted_{data}"
    
    # Mock implementation of decrypt_string
    def mock_decrypt_string(encrypted_data: str) -> str:
        if encrypted_data is None:
            return None
            
        # Remove version prefix if present
        if encrypted_data.startswith("v1:"):
            encrypted_data = encrypted_data[3:]
            
        if encrypted_data.startswith("encrypted_"):
            return encrypted_data[len("encrypted_"):]
            
        return encrypted_data

    # Set up the mock methods
    mock_service.encrypt = MagicMock(side_effect=mock_encrypt)
    mock_service.decrypt = MagicMock(side_effect=mock_decrypt)
    mock_service.encrypt_string = MagicMock(side_effect=mock_encrypt_string)
    mock_service.decrypt_string = MagicMock(side_effect=mock_decrypt_string)
    
    # Add version prefix property
    mock_service.VERSION_PREFIX = "v1:"
    
    return mock_service

@pytest.fixture # Defined only ONCE
def sample_domain_patient_data() -> dict:
    return {
        "id": uuid.uuid4(),
        "first_name": "JohnDomain",
        "last_name": "DoeDomain",
        "date_of_birth": date(1990, 1, 15),
        "email": "john.domain@example.com",
        "phone_number": "555-0101",
        "medical_record_number_lve": "MRNDOMAIN123",
        "ssn": "123-45-6789",  # Add SSN
        "social_security_number_lve": "123-45-6789",  # Add with _lve suffix
        "insurance_policy_number": "POLICY123",  # Add insurance policy number
        "insurance_provider": "MockInsuranceCo",  # Add insurance provider 
        "allergies_reactions": ["Penicillin: Rash", "Peanuts: Anaphylaxis"],  # Add allergies
        "medications_supplements": ["Medication: MockMed, Dosage: 10mg daily"],  # Add medications
        "treatment_plans": ["Weekly therapy sessions", "Daily mindfulness practice"],  # Add treatment plans
        "preferences_restrictions": {"diet": "Vegetarian", "activity": "No high-impact exercise"},  # Add preferences
        "custom_fields": {"preferred_language": "English", "referred_by": "Dr. Smith"},  # Add custom fields
        "medical_history": [
            "Condition: Flu, Diagnosed Date: 2023-01-10",
            "Condition: Mockitis, Diagnosed Date: 2020-01-01"
        ],
        "emergency_contacts": [  # Add emergency contacts
            {
                "name": "Jane Doe",
                "relationship": "Spouse",
                "phone": "555-0303"
            }
        ],
        "gender": Gender.MALE,
        "address": {
            "street": "123 Domain Lane",
            "line2": "Apt 4B",
            "city": "Domainville",
            "state": "DS",
            "zip_code": "12345",
            "country": "DX"
        },
        "contact_info": {
            "email": "john.domain.contact@example.com",
            "phone": "555-0202",
            "email_secondary": "john.domain.secondary@example.com"
        }
    }

class TestPatientModelEncryptionAndTypes:
    """Tests for PatientModel TypeDecorators and encryption-related methods."""

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.types.encrypted_types.global_encryption_service_instance')
    async def test_encrypted_string_process_bind_param(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedString.process_bind_param calls encrypt_string."""
        # Set up the mock to handle the encrypt_string call, not just encrypt
        mock_esi.encrypt_string = mock_encryption_service_for_model_tests.encrypt_string
        
        # Create an instance with the patched service
        decorator = EncryptedString(encryption_service=mock_esi)
        plaintext = "sensitive_info"
        
        # Call the method
        encrypted_value = decorator.process_bind_param(plaintext, None)
        
        # Verify the mock was called with the plaintext
        mock_esi.encrypt_string.assert_called_once_with(plaintext)
        assert encrypted_value == f"encrypted_{plaintext}"

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.types.encrypted_types.global_encryption_service_instance')
    async def test_encrypted_string_process_result_value(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedString.process_result_value calls decrypt_string."""
        # Set up the mock for decrypt_string, not just decrypt
        mock_esi.decrypt_string = mock_encryption_service_for_model_tests.decrypt_string
        
        # Create a versioned encrypted string
        encrypted_text = "v1:encrypted_sensitive_info"
        
        # Create an instance with the patched service
        decorator = EncryptedString(encryption_service=mock_esi)
        
        # Call the method
        decrypted_value = decorator.process_result_value(encrypted_text, None)
        
        # Verify the mock was called correctly
        mock_esi.decrypt_string.assert_called_once_with(encrypted_text)
        assert decrypted_value == "sensitive_info"

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.types.encrypted_types.global_encryption_service_instance')
    async def test_encrypted_json_process_bind_param(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_bind_param calls json.dumps and encrypt_string."""
        # Set up the mock for encrypt_string, not just encrypt
        mock_esi.encrypt_string = mock_encryption_service_for_model_tests.encrypt_string
        
        # Create an instance with the patched service
        decorator = EncryptedJSON(encryption_service=mock_esi)
        python_object = {"key": "value", "list": [1, 2, {"sub_key": "sub_val"}]}
        
        # Call the method
        encrypted_value = decorator.process_bind_param(python_object, None)
        
        # Verify the mock was called with the serialized JSON
        assert mock_esi.encrypt_string.called
        assert encrypted_value.startswith("encrypted_")
        # The encryption value will depend on the mock, but we can just check basic behaviors

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    @pytest.mark.asyncio
    async def test_encrypted_json_process_result_value(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON._convert_result_value properly handles JSON parsing."""
        # Create a decorator instance
        decorator = EncryptedJSON()
        
        # Test data
        original_python_object = {"key": "value", "list": [1, 2, {"sub_key": "sub_val"}]}
        json_string_of_original = json.dumps(original_python_object)
        
        # Test the _convert_result_value method directly
        # This is what's called after decrypt returns a string
        result = decorator._convert_result_value(json_string_of_original)
        
        # Assert the JSON was correctly parsed
        assert result == original_python_object

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    @pytest.mark.asyncio
    async def test_encrypted_json_process_result_value_handles_none(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_result_value handles None input gracefully."""
        mock_esi.decrypt = mock_encryption_service_for_model_tests.decrypt
        decorator = EncryptedJSON()
        assert decorator.process_result_value(None, None) is None
        mock_encryption_service_for_model_tests.decrypt.assert_not_called()

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    @pytest.mark.asyncio
    async def test_encrypted_json_process_bind_param_handles_none(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_bind_param handles None input gracefully."""
        mock_esi.encrypt = mock_encryption_service_for_model_tests.encrypt
        decorator = EncryptedJSON()
        assert decorator.process_bind_param(None, None) is None
        mock_encryption_service_for_model_tests.encrypt.assert_not_called()

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    @pytest.mark.asyncio
    async def test_patient_model_to_domain(
        self,
        mock_esi: MagicMock, # This is the ESI for TypeDecorators
        sample_domain_patient_data: dict,
        mock_encryption_service_for_model_tests: MagicMock # Separate mock for direct model use if any
    ):
        """Test converting a PatientModel with encrypted fields to a PatientEntity,
        ensuring precise decryption via mocked ESI for TypeDecorators.
        """
        logger.info(f"Starting test_patient_model_to_domain with sample data: {sample_domain_patient_data}")

        # Setup the mock for decrypt to strip the 'encrypted_' prefix
        def mock_decrypt(encrypted_value):
            if isinstance(encrypted_value, str) and encrypted_value.startswith('encrypted_'):
                # Get the value without the prefix
                decrypted_value = encrypted_value[len('encrypted_'):]
                # For date_of_birth, ensure it returns a properly formatted date string
                return decrypted_value
            return encrypted_value
            
        mock_esi.decrypt.side_effect = mock_decrypt
        mock_esi.VERSION_PREFIX = 'v1:'
        mock_esi.decrypt_string.side_effect = mock_decrypt

        # Create a model instance and set encrypted fields directly
        # In a real scenario, these would come from the database already encrypted
        model_instance = PatientModel()
        model_instance.id = sample_domain_patient_data["id"]
        model_instance._first_name = f"encrypted_{sample_domain_patient_data['first_name']}"
        model_instance._last_name = f"encrypted_{sample_domain_patient_data['last_name']}"
        model_instance._email = f"encrypted_{sample_domain_patient_data['email']}"
        
        # Set date of birth as a string (since that's how it would be stored)
        dob_str = sample_domain_patient_data["date_of_birth"].isoformat()
        model_instance._date_of_birth = f"encrypted_{dob_str}"
        logger.info(f"Set model_instance._date_of_birth to: '{model_instance._date_of_birth}'")
        
        # Set gender - normally an Enum value in the domain but stored as string in DB
        model_instance._gender = sample_domain_patient_data["gender"].value # Set directly as the Enum value
        
        # Set other fields
        model_instance._phone_number = f"encrypted_{sample_domain_patient_data['phone_number']}"
        model_instance._mrn = f"encrypted_{sample_domain_patient_data['medical_record_number_lve']}"
        
        # Set complex fields by directly JSONifying them
        model_instance._medical_history = f"encrypted_{json.dumps(sample_domain_patient_data['medical_history'])}"
        model_instance._contact_info = sample_domain_patient_data["contact_info"]
        
        # Call to_domain
        logger.info(f"Calling model_instance.to_domain()...")
        domain_entity = await model_instance.to_domain()
        
        # Verify the domain entity has the correct values
        assert domain_entity.id == sample_domain_patient_data["id"]
        assert domain_entity.first_name == sample_domain_patient_data["first_name"]
        assert domain_entity.last_name == sample_domain_patient_data["last_name"]
        assert domain_entity.email == sample_domain_patient_data["email"]
        assert domain_entity.medical_record_number_lve == sample_domain_patient_data["medical_record_number_lve"]
        
        # Check date_of_birth specifically - it needs to parse correctly from the string format
        assert domain_entity.date_of_birth is not None
        assert isinstance(domain_entity.date_of_birth, date)
        assert domain_entity.date_of_birth == sample_domain_patient_data["date_of_birth"]

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    @pytest.mark.asyncio
    async def test_patient_model_from_domain(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock, sample_domain_patient_data: dict):
        """Test PatientModel.from_domain sets attributes correctly.
        Encryption itself is handled by TypeDecorator on flush, not by from_domain.
        """
        mock_esi.encrypt = mock_encryption_service_for_model_tests.encrypt

        domain_patient = DomainPatient(**sample_domain_patient_data)
        
        model_instance = await PatientModel.from_domain(domain_patient)

        assert model_instance._first_name == sample_domain_patient_data["first_name"]
        assert model_instance._last_name == sample_domain_patient_data["last_name"]
        assert model_instance._email == sample_domain_patient_data["email"]
        assert model_instance._mrn == sample_domain_patient_data["medical_record_number_lve"]
        assert model_instance._medical_history == json.dumps(sample_domain_patient_data["medical_history"])

        mock_encryption_service_for_model_tests.encrypt.assert_not_called()
