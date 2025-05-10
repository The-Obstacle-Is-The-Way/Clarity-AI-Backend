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

import pytest

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

    def mock_encrypt_sync(raw_string: str) -> str:
        if not isinstance(raw_string, str):
            raw_string = str(raw_string) 
        return f"encrypted_{raw_string}"

    def mock_decrypt_sync(encrypted_string: str) -> str:
        if not isinstance(encrypted_string, str):
            return str(encrypted_string) 
        if encrypted_string.startswith("encrypted_"):
            return encrypted_string[len("encrypted_"):]
        return encrypted_string

    mock_service.encrypt = MagicMock(side_effect=mock_encrypt_sync)
    mock_service.decrypt = MagicMock(side_effect=mock_decrypt_sync)
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
        "medical_history": [
            "Condition: Flu, Diagnosed Date: 2023-01-10",
            "Condition: Mockitis, Diagnosed Date: 2020-01-01"
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
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_string_process_bind_param(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedString.process_bind_param calls encrypt_string."""
        mock_esi.encrypt = mock_encryption_service_for_model_tests.encrypt
        
        decorator = EncryptedString() 
        plaintext = "sensitive_info"
        
        encrypted_value = decorator.process_bind_param(plaintext, None)
        
        mock_encryption_service_for_model_tests.encrypt.assert_called_once_with(plaintext)
        assert encrypted_value == f"encrypted_{plaintext}"

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_string_process_result_value(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedString.process_result_value calls decrypt_string."""
        mock_esi.decrypt = mock_encryption_service_for_model_tests.decrypt

        decorator = EncryptedString()
        encrypted_text = "encrypted_sensitive_info"
        
        decrypted_value = decorator.process_result_value(encrypted_text, None)
        
        mock_encryption_service_for_model_tests.decrypt.assert_called_once_with(encrypted_text)
        assert decrypted_value == "sensitive_info"

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_json_process_bind_param(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_bind_param calls json.dumps and encrypt_string."""
        mock_esi.encrypt = mock_encryption_service_for_model_tests.encrypt
        
        decorator = EncryptedJSON()
        python_object = {"key": "value", "list": [1, 2, {"sub_key": "sub_val"}]}
        expected_json_string = json.dumps(python_object)
        
        encrypted_value = decorator.process_bind_param(python_object, None)
        
        mock_encryption_service_for_model_tests.encrypt.assert_called_once_with(expected_json_string)
        assert encrypted_value == f"encrypted_{expected_json_string}"

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_json_process_result_value(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_result_value calls decrypt_string and json.loads."""
        mock_esi.decrypt = mock_encryption_service_for_model_tests.decrypt

        decorator = EncryptedJSON()
        original_python_object = {"key": "value", "list": [1, 2, {"sub_key": "sub_val"}]}
        json_string_of_original = json.dumps(original_python_object)
        encrypted_db_text = f"encrypted_{json_string_of_original}"
        
        mock_encryption_service_for_model_tests.decrypt.return_value = json_string_of_original

        decrypted_object = decorator.process_result_value(encrypted_db_text, None)
        
        mock_encryption_service_for_model_tests.decrypt.assert_called_once_with(encrypted_db_text)
        assert decrypted_object == original_python_object

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_json_process_result_value_handles_none(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_result_value handles None input gracefully."""
        mock_esi.decrypt = mock_encryption_service_for_model_tests.decrypt
        decorator = EncryptedJSON()
        assert decorator.process_result_value(None, None) is None
        mock_encryption_service_for_model_tests.decrypt.assert_not_called()

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_json_process_bind_param_handles_none(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_bind_param handles None input gracefully."""
        mock_esi.encrypt = mock_encryption_service_for_model_tests.encrypt
        decorator = EncryptedJSON()
        assert decorator.process_bind_param(None, None) is None
        mock_encryption_service_for_model_tests.encrypt.assert_not_called()

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_patient_model_to_domain(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock, sample_domain_patient_data: dict):
        """Test PatientModel.to_domain correctly calls decrypt_string via TypeDecorators."""
        mock_esi.decrypt = mock_encryption_service_for_model_tests.decrypt

        model_instance = PatientModel()
        model_instance.id = sample_domain_patient_data["id"]
        
        # This map helps the decrypt side_effect return the correct original plaintext
        expected_plaintext_map = {
            "_first_name": sample_domain_patient_data['first_name'],
            "_last_name": sample_domain_patient_data['last_name'],
            "_email": sample_domain_patient_data['email'],
            "_mrn": sample_domain_patient_data['medical_record_number_lve'], 
            "_date_of_birth": sample_domain_patient_data["date_of_birth"].isoformat(), # Plain string '1990-01-15'
            "_address_line1": sample_domain_patient_data['address']['street'],
            "_city": sample_domain_patient_data['address']['city'],
            "_state": sample_domain_patient_data['address']['state'],
            "_zip_code": sample_domain_patient_data['address']['zip_code'],
            "_country": sample_domain_patient_data['address']['country'],
            "_medical_history": json.dumps(sample_domain_patient_data['medical_history']),
            "_gender": sample_domain_patient_data['gender'].value if sample_domain_patient_data.get('gender') else None,
            # Add other encrypted fields from PatientModel that are set from sample_domain_patient_data
        }

        # Define a more precise side_effect for decryption
        def precise_decrypt_side_effect(encrypted_input_val):
            # logger.debug(f"[decrypt_side_effect] Received: {encrypted_input_val}")
            
            # Explicit handling for date_of_birth to ensure it's correctly processed
            # sample_domain_patient_data["date_of_birth"] is date(1990, 1, 15)
            expected_plain_dob_str = sample_domain_patient_data["date_of_birth"].isoformat() # "1990-01-15"
            expected_encrypted_dob_str = f"encrypted_{expected_plain_dob_str}" # "encrypted_1990-01-15"

            if encrypted_input_val == expected_encrypted_dob_str:
                # logger.debug(f"[decrypt_side_effect] Matched DOB: {encrypted_input_val} -> {expected_plain_dob_str}")
                return expected_plain_dob_str

            # Direct mappings for other expected_plaintext_map items
            for plain_key, plain_value in expected_plaintext_map.items():
                if plain_key == "_date_of_birth": # Already handled above
                    continue

                if plain_value is None:
                    if encrypted_input_val is None:
                        # logger.debug(f"[decrypt_side_effect] Matched None -> None for key {plain_key}")
                        return None
                    continue
                
                expected_encrypted_form = f"encrypted_{plain_value}"
                if encrypted_input_val == expected_encrypted_form:
                    # logger.debug(f"[decrypt_side_effect] Matched '{encrypted_input_val}' -> '{plain_value}' for key {plain_key}")
                    return plain_value
            
            # Fallback if no specific match - this indicates an issue in test setup or an unmapped field
            # logger.warning(f"[decrypt_side_effect] No precise match for '{encrypted_input_val}', returning as is. This might cause test failures.")
            return encrypted_input_val

        mock_esi.decrypt = precise_decrypt_side_effect 

        # Values that will be set on the model instance (simulating encrypted DB state)
        encrypted_model_values = {key: f"encrypted_{value}" if value is not None else None 
                                  for key, value in expected_plaintext_map.items()}

        # Set model attributes to their "encrypted" form
        model_instance._first_name = encrypted_model_values['_first_name']
        model_instance._last_name = encrypted_model_values['_last_name']
        model_instance._email = encrypted_model_values['_email']
        model_instance._mrn = encrypted_model_values['_mrn'] 
        model_instance._date_of_birth = encrypted_model_values['_date_of_birth']
        model_instance._medical_history = encrypted_model_values['_medical_history']
        if expected_plaintext_map['_gender']:
            model_instance._gender = encrypted_model_values['_gender']

        domain_entity = await model_instance.to_domain()

        assert domain_entity.id == sample_domain_patient_data["id"]
        assert domain_entity.first_name == expected_plaintext_map["_first_name"]
        assert domain_entity.last_name == expected_plaintext_map["_last_name"]
        assert domain_entity.email == expected_plaintext_map["_email"]
        assert domain_entity.medical_record_number_lve == expected_plaintext_map["_mrn"]
        assert domain_entity.medical_history == sample_domain_patient_data["medical_history"] # medical_history is already list[str]
        assert domain_entity.date_of_birth == sample_domain_patient_data["date_of_birth"]
        if sample_domain_patient_data.get("gender"):
             assert domain_entity.gender == sample_domain_patient_data["gender"]

        # Check that decrypt was called for accessed fields. 
        # Expected calls: _first_name, _last_name, _email, _mrn, _date_of_birth, _medical_history
        # Plus _gender if it was set.
        expected_decrypt_calls = 6 + (1 if expected_plaintext_map['_gender'] else 0)
        assert mock_encryption_service_for_model_tests.decrypt.call_count >= expected_decrypt_calls

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
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
