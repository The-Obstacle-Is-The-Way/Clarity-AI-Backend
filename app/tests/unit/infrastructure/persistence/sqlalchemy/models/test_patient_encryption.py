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
        "medical_record_number_lve": "MRNDOMAIN123",
        "medical_history": [
            "Condition: Flu, Diagnosed Date: 2023-01-10",
            "Condition: Mockitis, Diagnosed Date: 2020-01-01"
        ],
        "gender": Gender.MALE,
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
        
        fields_to_encrypt_map = {
            "_first_name": sample_domain_patient_data['first_name'],
            "_last_name": sample_domain_patient_data['last_name'],
            "_email": sample_domain_patient_data['email'],
            "_medical_record_number": sample_domain_patient_data['medical_record_number_lve'],
            "_date_of_birth": sample_domain_patient_data["date_of_birth"].isoformat(),
            "_medical_history": json.dumps(sample_domain_patient_data["medical_history"]),
            "_gender": sample_domain_patient_data['gender'].value if sample_domain_patient_data.get("gender") else None
        }
        
        def decrypt_side_effect(encrypted_val):
            if encrypted_val == f"encrypted_{fields_to_encrypt_map['_first_name']}": return fields_to_encrypt_map['_first_name']
            if encrypted_val == f"encrypted_{fields_to_encrypt_map['_last_name']}": return fields_to_encrypt_map['_last_name']
            if encrypted_val == f"encrypted_{fields_to_encrypt_map['_email']}": return fields_to_encrypt_map['_email']
            if encrypted_val == f"encrypted_{fields_to_encrypt_map['_medical_record_number']}": return fields_to_encrypt_map['_medical_record_number']
            if encrypted_val == f"encrypted_{fields_to_encrypt_map['_date_of_birth']}": return fields_to_encrypt_map['_date_of_birth']
            if encrypted_val == f"encrypted_{fields_to_encrypt_map['_medical_history']}": return fields_to_encrypt_map['_medical_history']
            if fields_to_encrypt_map['_gender'] and encrypted_val == f"encrypted_{fields_to_encrypt_map['_gender']}": return fields_to_encrypt_map['_gender']
            return encrypted_val
        
        mock_encryption_service_for_model_tests.decrypt.side_effect = decrypt_side_effect

        model_instance._first_name = f"encrypted_{fields_to_encrypt_map['_first_name']}"
        model_instance._last_name = f"encrypted_{fields_to_encrypt_map['_last_name']}"
        model_instance._email = f"encrypted_{fields_to_encrypt_map['_email']}"
        model_instance._mrn = f"encrypted_{fields_to_encrypt_map['_medical_record_number']}"
        model_instance._date_of_birth = f"encrypted_{fields_to_encrypt_map['_date_of_birth']}"
        model_instance._medical_history = f"encrypted_{fields_to_encrypt_map['_medical_history']}"
        if fields_to_encrypt_map['_gender']:
            model_instance._gender = f"encrypted_{fields_to_encrypt_map['_gender']}"

        domain_entity = await model_instance.to_domain()

        assert domain_entity.id == sample_domain_patient_data["id"]
        assert domain_entity.first_name == sample_domain_patient_data["first_name"]
        assert domain_entity.last_name == sample_domain_patient_data["last_name"]
        assert domain_entity.email == sample_domain_patient_data["email"]
        assert domain_entity.medical_record_number_lve == sample_domain_patient_data["medical_record_number_lve"]
        assert domain_entity.medical_history == sample_domain_patient_data["medical_history"]
        assert domain_entity.date_of_birth == sample_domain_patient_data["date_of_birth"]
        if sample_domain_patient_data.get("gender"):
             assert domain_entity.gender == sample_domain_patient_data["gender"]

        assert mock_encryption_service_for_model_tests.decrypt.call_count >= 6

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
