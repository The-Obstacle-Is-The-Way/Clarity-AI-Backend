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

        # This map defines the PLAINTEXT values we expect AFTER decryption for model attributes
        # It includes fields that are handled by TypeDecorators (e.g., _first_name, _date_of_birth)
        # and also fields that might be part of EncryptedJSON (_contact_info contents).
        expected_plaintext_map = {
            "_first_name": sample_domain_patient_data["first_name"],
            "_last_name": sample_domain_patient_data["last_name"],
            "_email": sample_domain_patient_data["email"],
            # DOB is stored as string after encryption, so use its ISO format string here
            "_date_of_birth": sample_domain_patient_data["date_of_birth"].isoformat(),
            "_ssn": sample_domain_patient_data["ssn"],
            "_gender": sample_domain_patient_data["gender"].value, # Store enum value
            "_address_line1": sample_domain_patient_data["address"]["street"], # from 'street'
            "_city": sample_domain_patient_data["address"]["city"],
            "_state": sample_domain_patient_data["address"]["state"],
            "_zip_code": sample_domain_patient_data["address"]["zip_code"],
            "_country": sample_domain_patient_data["address"]["country"],
            "_phone_number": sample_domain_patient_data["phone_number"],
            "_medical_record_number": sample_domain_patient_data["medical_record_number"],
            "_insurance_policy_number": sample_domain_patient_data["insurance_policy_number"],
            # For EncryptedJSON fields, store the dict/list as the "plaintext" value
            "_contact_info": sample_domain_patient_data["contact_info"],
            "_emergency_contacts": sample_domain_patient_data["emergency_contacts"],
            "_medical_history": sample_domain_patient_data["medical_history"],
            "_allergies_reactions": sample_domain_patient_data["allergies_reactions"],
            "_medications_supplements": sample_domain_patient_data["medications_supplements"],
            "_treatment_plans": sample_domain_patient_data["treatment_plans"],
            "_preferences_restrictions": sample_domain_patient_data["preferences_restrictions"],
            "_custom_fields": sample_domain_patient_data["custom_fields"],
        }
        logger.debug(f"Expected plaintext map for model attributes: {expected_plaintext_map}")

        # Side effect for the ESI mock used by TypeDecorators
        # This function needs to correctly return the PLAINTEXT value when given an ENCRYPTED value
        def precise_decrypt_side_effect(encrypted_input_val):
            # Ensure encrypted_input_val is a plain string for comparison and diagnostics
            input_val_as_str = str(encrypted_input_val)

            # Construct the target encrypted DOB string from known good components
            # Ensure components are strings before f-string formatting
            plain_dob_from_map = str(expected_plaintext_map["_date_of_birth"]) # Should be "1990-01-15"
            target_encrypted_dob_str = f"encrypted_{plain_dob_from_map}"     # Should be "encrypted_1990-01-15"

            logger.critical(
                f"SIDE_EFFECT_DEBUG: Comparing Input='{input_val_as_str!r}' (orig type: {type(encrypted_input_val)}, type_as_str: {type(input_val_as_str)}) "
                f"AGAINST TargetEncryptedDOB='{target_encrypted_dob_str!r}' (type: {type(target_encrypted_dob_str)})"
            )

            if input_val_as_str == target_encrypted_dob_str:
                logger.critical(f"SIDE_EFFECT_DEBUG: DOB MATCH SUCCESS! Input='{input_val_as_str!r}' matched Target='{target_encrypted_dob_str!r}'. Returning plain: '{plain_dob_from_map!r}'")
                return plain_dob_from_map # Return the plain string "1990-01-15"
            else:
                logger.error(
                    f"SIDE_EFFECT_DEBUG: DOB MATCH FAILED! Input='{input_val_as_str!r}' (len {len(input_val_as_str)}) "
                    f"did NOT MATCH Target='{target_encrypted_dob_str!r}' (len {len(target_encrypted_dob_str)})."
                )
                # For detailed character-by-character comparison if needed:
                # for i in range(min(len(input_val_as_str), len(target_encrypted_dob_str))):
                #     if input_val_as_str[i] != target_encrypted_dob_str[i]:
                #         logger.error(f"Mismatch at index {i}: Input '{input_val_as_str[i]}' (ord {ord(input_val_as_str[i])}) != Target '{target_encrypted_dob_str[i]}' (ord {ord(target_encrypted_dob_str[i])})")
                #         break
                # if len(input_val_as_str) != len(target_encrypted_dob_str):
                #     logger.error("Lengths are different.")


            # Fallback for other non-DOB fields (general logic)
            # This part should only execute if the DOB didn't match and take the fallback path.
            for model_attr_name_loop, plain_value_loop in expected_plaintext_map.items():
                if model_attr_name_loop == "_date_of_birth": # Already handled, or failed and will go to outer fallback
                    continue

                plain_value_str_loop = str(plain_value_loop) if plain_value_loop is not None else None
                
                if plain_value_str_loop is None:
                    if input_val_as_str is None or input_val_as_str == str(None): # handle case where None becomes "None"
                        # logger.debug(f"[decrypt_side_effect] Matched None for '{model_attr_name_loop}'. Returning None.")
                        return None # Correctly return None, not "None"
                    continue

                expected_encrypted_form_loop = f"encrypted_{plain_value_str_loop}"
                if input_val_as_str == expected_encrypted_form_loop:
                    # logger.debug(f"[decrypt_side_effect] Loop match for '{model_attr_name_loop}'. Returning: {plain_value_str_loop!r}")
                    return plain_value_str_loop
            
            logger.warning(f"SIDE_EFFECT_DEBUG: No specific match for '{input_val_as_str!r}' after DOB check and loop. Returning as is (fallback).")
            return input_val_as_str # Fallback path

        # mock_esi.decrypt_string = AsyncMock(side_effect=precise_decrypt_side_effect) # This was incorrect for EncryptedString
        # The TypeDecorator EncryptedString uses `esi.decrypt(value)`
        # So, we mock the `decrypt` attribute of `mock_esi` (which is already a MagicMock)
        mock_esi.decrypt.side_effect = precise_decrypt_side_effect


        # --- Setup Model Instance with "Encrypted" Data ---
        model_instance = PatientModel(id=sample_domain_patient_data["id"])

        # Simulate how data would look if loaded from DB (i.e., "encrypted")
        # These will be the values that TypeDecorators' process_result_value will receive
        for attr_name, plain_val in expected_plaintext_map.items():
            if hasattr(model_instance, attr_name):
                if plain_val is None:
                    setattr(model_instance, attr_name, None)
                elif isinstance(plain_val, (dict, list)): # For JSON fields
                    # EncryptedJSON stringifies, then encrypts. So simulate the "encrypted" (but actually just prefixed) string.
                    json_str = json.dumps(plain_val, sort_keys=True)
                    # Wrap it like EncryptedJSON's TypeDecorator might present it after initial decryption of the outer layer
                    # This is a bit of a guess, assuming EncryptedJSON uses a wrapper or decrypts to a string first.
                    # For simplicity, let's assume the type decorator's 'value' for esi.decrypt is the raw encrypted string.
                    setattr(model_instance, attr_name, f"encrypted_{json_str}")
                else:
                    # For simple string fields like _first_name, _date_of_birth (which is string '1990-01-15' in map)
                    if attr_name == "_date_of_birth":
                         # Use a distinct placeholder to ensure the specific DOB check in side_effect is tested if direct set matters
                         # setattr(model_instance, attr_name, "_date_of_birth_encrypted_value_placeholder_from_model_setup")
                         setattr(model_instance, attr_name, f"encrypted_{plain_val}") # Standard encryption simulation
                         logger.info(f"Set model_instance._date_of_birth to: {model_instance._date_of_birth!r}")

                    else:
                         setattr(model_instance, attr_name, f"encrypted_{plain_val}")


        # --- Call to_domain ---
        logger.info("Calling model_instance.to_domain()...")
        domain_entity = await model_instance.to_domain()

        assert domain_entity.id == sample_domain_patient_data["id"]
        assert domain_entity.first_name == expected_plaintext_map["_first_name"]
        assert domain_entity.last_name == expected_plaintext_map["_last_name"]
        assert domain_entity.email == expected_plaintext_map["_email"]
        assert domain_entity.medical_record_number_lve == expected_plaintext_map["_medical_record_number"]
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
