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

logger = logging.getLogger(__name__)

@pytest.fixture
def mock_encryption_service_for_model_tests() -> MagicMock:
    """Provides a mock encryption service for model/TypeDecorator tests."""
    mock_service = MagicMock(spec=BaseEncryptionService)

    async def mock_encrypt_string(raw_string: str) -> str:
        if not isinstance(raw_string, str):
            raw_string = str(raw_string) 
        return f"encrypted_{raw_string}"

    async def mock_decrypt_string(encrypted_string: str) -> str:
        if not isinstance(encrypted_string, str):
            return str(encrypted_string) 
        if encrypted_string.startswith("encrypted_"):
            return encrypted_string[len("encrypted_"):]
        return encrypted_string

    mock_service.encrypt_string = AsyncMock(side_effect=mock_encrypt_string)
    mock_service.decrypt_string = AsyncMock(side_effect=mock_decrypt_string)
    return mock_service

@pytest.fixture # Defined only ONCE
def sample_domain_patient_data() -> dict:
    return {
        "id": uuid.uuid4(),
        "first_name": "JohnDomain",
        "last_name": "DoeDomain",
        "date_of_birth": date(1990, 1, 15),
        "email": "john.domain@example.com",
        "medical_record_number": "MRNDOMAIN123",
        "medical_history": [{"condition": "Flu", "diagnosed_date": "2023-01-10"}],
    }

class TestPatientModelEncryptionAndTypes:
    """Tests for PatientModel TypeDecorators and encryption-related methods."""

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_string_process_bind_param(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedString.process_bind_param calls encrypt_string."""
        mock_esi.encrypt_string = mock_encryption_service_for_model_tests.encrypt_string
        
        decorator = EncryptedString() 
        plaintext = "sensitive_info"
        
        encrypted_value = await decorator.process_bind_param(plaintext, None) 
        
        mock_encryption_service_for_model_tests.encrypt_string.assert_awaited_once_with(plaintext)
        assert encrypted_value == f"encrypted_{plaintext}"

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_string_process_result_value(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedString.process_result_value calls decrypt_string."""
        mock_esi.decrypt_string = mock_encryption_service_for_model_tests.decrypt_string

        decorator = EncryptedString()
        encrypted_text = "encrypted_sensitive_info"
        
        decrypted_value = await decorator.process_result_value(encrypted_text, None)
        
        mock_encryption_service_for_model_tests.decrypt_string.assert_awaited_once_with(encrypted_text)
        assert decrypted_value == "sensitive_info"

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_json_process_bind_param(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_bind_param calls json.dumps and encrypt_string."""
        mock_esi.encrypt_string = mock_encryption_service_for_model_tests.encrypt_string
        
        decorator = EncryptedJSON()
        python_object = {"key": "value", "list": [1, 2, {"sub_key": "sub_val"}]}
        expected_json_string = json.dumps(python_object)
        
        encrypted_value = await decorator.process_bind_param(python_object, None)
        
        mock_encryption_service_for_model_tests.encrypt_string.assert_awaited_once_with(expected_json_string)
        assert encrypted_value == f"encrypted_{expected_json_string}"

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_json_process_result_value(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_result_value calls decrypt_string and json.loads."""
        mock_esi.decrypt_string = mock_encryption_service_for_model_tests.decrypt_string

        decorator = EncryptedJSON()
        original_python_object = {"key": "value", "list": [1, 2, {"sub_key": "sub_val"}]}
        json_string_of_original = json.dumps(original_python_object)
        encrypted_db_text = f"encrypted_{json_string_of_original}"
        
        decrypted_object = await decorator.process_result_value(encrypted_db_text, None)
        
        mock_encryption_service_for_model_tests.decrypt_string.assert_awaited_once_with(encrypted_db_text)
        assert decrypted_object == original_python_object

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_json_process_result_value_handles_none(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_result_value handles None input gracefully."""
        mock_esi.decrypt_string = mock_encryption_service_for_model_tests.decrypt_string
        decorator = EncryptedJSON()
        assert await decorator.process_result_value(None, None) is None
        mock_encryption_service_for_model_tests.decrypt_string.assert_not_called()

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_encrypted_json_process_bind_param_handles_none(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock):
        """Test EncryptedJSON.process_bind_param handles None input gracefully."""
        mock_esi.encrypt_string = mock_encryption_service_for_model_tests.encrypt_string
        decorator = EncryptedJSON()
        assert await decorator.process_bind_param(None, None) is None
        mock_encryption_service_for_model_tests.encrypt_string.assert_not_called()

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_patient_model_to_domain(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock, sample_domain_patient_data: dict):
        """Test PatientModel.to_domain correctly calls decrypt_string via TypeDecorators."""
        mock_esi.decrypt_string = mock_encryption_service_for_model_tests.decrypt_string

        model_instance = PatientModel()
        model_instance.id = sample_domain_patient_data["id"]
        model_instance._first_name = await mock_encryption_service_for_model_tests.encrypt_string(sample_domain_patient_data["first_name"])
        model_instance._last_name = await mock_encryption_service_for_model_tests.encrypt_string(sample_domain_patient_data["last_name"])
        model_instance._email = await mock_encryption_service_for_model_tests.encrypt_string(sample_domain_patient_data["email"])
        model_instance._medical_record_number = await mock_encryption_service_for_model_tests.encrypt_string(sample_domain_patient_data["medical_record_number"])
        
        medical_history_json = json.dumps(sample_domain_patient_data["medical_history"])
        model_instance._medical_history = await mock_encryption_service_for_model_tests.encrypt_string(medical_history_json)

        domain_entity = await model_instance.to_domain()

        assert domain_entity.id == sample_domain_patient_data["id"]
        assert domain_entity.first_name == sample_domain_patient_data["first_name"]
        assert domain_entity.last_name == sample_domain_patient_data["last_name"]
        assert domain_entity.email == sample_domain_patient_data["email"]
        assert domain_entity.medical_record_number == sample_domain_patient_data["medical_record_number"]
        assert domain_entity.medical_history == sample_domain_patient_data["medical_history"]

        calls = [
            mock_encryption_service_for_model_tests.decrypt_string.await_args_list[i][0][0] for i in range(mock_encryption_service_for_model_tests.decrypt_string.await_count)
        ]
        assert model_instance._first_name in calls
        assert model_instance._last_name in calls
        assert model_instance._email in calls
        assert model_instance._medical_record_number in calls
        assert model_instance._medical_history in calls
        assert mock_encryption_service_for_model_tests.decrypt_string.await_count >= 5

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_patient_model_from_domain(self, mock_esi: MagicMock, mock_encryption_service_for_model_tests: MagicMock, sample_domain_patient_data: dict):
        """Test PatientModel.from_domain sets attributes correctly.
        Encryption itself is handled by TypeDecorator on flush, not by from_domain.
        """
        mock_esi.encrypt_string = mock_encryption_service_for_model_tests.encrypt_string

        domain_patient = DomainPatient(**sample_domain_patient_data)
        
        model_instance = await PatientModel.from_domain(domain_patient)

        assert model_instance._first_name == sample_domain_patient_data["first_name"]
        assert model_instance._last_name == sample_domain_patient_data["last_name"]
        assert model_instance._email == sample_domain_patient_data["email"]
        assert model_instance._medical_record_number == sample_domain_patient_data["medical_record_number"]
        assert model_instance._medical_history == sample_domain_patient_data["medical_history"]

        mock_encryption_service_for_model_tests.encrypt_string.assert_not_called()
