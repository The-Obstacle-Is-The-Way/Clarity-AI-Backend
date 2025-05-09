"""Unit tests for the Patient repository SQLAlchemy implementation.

This module tests the functionality of the PatientRepository class to ensure
that it correctly interacts with the database layer, properly handling
patient data in accordance with HIPAA and other security requirements.
"""

import asyncio
import base64
import json
import logging
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.patient import Patient as PatientEntity
from app.infrastructure.persistence.sqlalchemy.models.patient import Patient as PatientModel
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepository,
)
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService


@pytest.fixture
def sample_patient_id() -> str:
    """Return a consistent UUID for testing."""
    return "12345678-1234-5678-1234-567812345678"


@pytest.fixture
def sample_patient_data(sample_patient_id: str) -> dict[str, Any]:
    """Create sample patient data for testing."""
    return {
        "id": sample_patient_id,
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1980-01-01",
        "medical_record_number": "MRN12345",
        "email": "john.doe@example.com"
    }


@pytest_asyncio.fixture
async def async_mock_patch():
    """Handle non-awaited coroutines in tests by patching AsyncMock."""
    # Create a helper for safely awaiting coroutines
    async def safe_await(coro_or_value):
        if asyncio.iscoroutine(coro_or_value):
            return await coro_or_value
        return coro_or_value
    
    # Patch AsyncMock.__call__ to handle both awaited and non-awaited calls
    original_call = AsyncMock.__call__
    
    async def patched_call(self, *args, **kwargs):
        result = original_call(self, *args, **kwargs)
        return await safe_await(result)
    
    with patch.object(AsyncMock, '__call__', patched_call):
        yield


@pytest.fixture
def mock_db_session() -> AsyncMock:
    """Provides a mock asynchronous session object."""
    session = AsyncMock(spec=AsyncSession)

    # Mock the execute method and its chained calls
    session.execute = AsyncMock()
    session.execute.return_value = AsyncMock()
    session.execute.return_value.scalar_one_or_none = AsyncMock()
    session.execute.return_value.scalars = AsyncMock()
    session.execute.return_value.scalars.return_value = AsyncMock()
    session.execute.return_value.scalars.return_value.all = MagicMock() # .all() is sync

    # Mock other session methods
    session.add = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.flush = AsyncMock()
    session.close = AsyncMock()
    session.get = AsyncMock() # Keep for delete path
    session.delete = AsyncMock()
    session.rollback = AsyncMock() # Add awaitable rollback

    # Mock context manager methods
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    # Mock the begin method and its context manager
    mock_transaction = AsyncMock()
    mock_transaction.__aenter__ = AsyncMock(return_value=None)
    mock_transaction.__aexit__ = AsyncMock(return_value=None)
    session.begin = MagicMock(return_value=mock_transaction) # begin() itself is sync

    return session


@pytest.fixture
def mock_encryption_service():
    """Fixture to create a mock encryption service aligning with BaseEncryptionService string methods."""
    mock_service = MagicMock(spec=BaseEncryptionService)

    # encrypt_string: str -> str (simulating string in, encrypted string out)
    async def mock_encrypt_string(raw_string: str) -> str:
        if not isinstance(raw_string, str):
            raise TypeError(f"Mock encrypt_string needs string input. Got {type(raw_string).__name__}")
        try:
            # Simulate encryption: string -> utf8 bytes -> base64 bytes -> base64 string
            encrypted_bytes = base64.b64encode(raw_string.encode('utf-8'))
            return encrypted_bytes.decode('utf-8') # Return as string
        except Exception as e:
            logging.error(f"Mock encrypt_string error: {e}")
            raise

    # decrypt_string: str -> str (simulating encrypted string in, decrypted string out)
    async def mock_decrypt_string(encrypted_string: str) -> str:
        if not isinstance(encrypted_string, str):
            raise TypeError(f"Mock decrypt_string needs string input. Got {type(encrypted_string).__name__}")
        try:
            # Simulate decryption: base64 string -> base64 bytes -> utf8 bytes -> string
            decrypted_bytes = base64.b64decode(encrypted_string.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            # Allow returning original string if b64decode fails, useful for non-encrypted test data
            logging.warning(f"Mock decrypt_string error: {e}. Returning original for testing.")
            return encrypted_string # Fallback for testing with plaintext

    mock_service.encrypt_string = AsyncMock(side_effect=mock_encrypt_string)
    mock_service.decrypt_string = AsyncMock(side_effect=mock_decrypt_string)
    
    # Add other methods from BaseEncryptionService as needed by tests, e.g., for EncryptedJSON
    # For now, assume EncryptedJSON also uses encrypt_string/decrypt_string with json.dumps/loads
    # If it uses encrypt_dict/decrypt_dict, those would need to be mocked here.

    return mock_service


@pytest.fixture
def patient_repository(mock_db_session) -> PatientRepository:
    """Create a PatientRepository instance for testing, providing a mock session factory."""
    # Create a mock factory function/object
    mock_session_factory = MagicMock() # Use MagicMock for a simple callable

    # Configure the factory to return the mock_db_session when called
    mock_session_factory.return_value = mock_db_session

    # Pass the FACTORY to the repository constructor
    return PatientRepository(db_session_factory=mock_session_factory,
                             user_context={"user_id": "test-user"})


# Helper to create mock PatientModel instances with 'encrypted' data for test setups
async def create_mock_patient_model_with_encrypted_data(
    patient_id_str: str,
    mock_encrypt_service: MagicMock, # Expecting the mock_encryption_service fixture
    raw_data_overrides: dict | None = None
) -> PatientModel:
    """Creates a mock PatientModel instance with specified fields 'encrypted' by mock_encrypt_service.

    Args:
        patient_id_str: The string UUID for the mock patient.
        mock_encrypt_service: The mock encryption service (fixture) to use for 'encrypting' fields.
        raw_data_overrides: A dictionary of plaintext values to override defaults before encryption.
                            Keys should be model attribute names (e.g., '_first_name').

    Returns:
        A PatientModel instance with sensitive fields mock-encrypted.
    """
    patient_uuid = uuid.UUID(patient_id_str)
    
    # Define default raw PII data (as strings or appropriate types before encryption)
    # Using model attribute names (e.g., _first_name)
    default_raw_pii = {
        "_first_name": "TestFirstName",
        "_last_name": "TestLastName",
        "_ssn": "999-99-9999",
        "_dob": date(1990, 1, 1), # Date object, not encrypted by encrypt_string
        "_email": "test.patient@example.com",
        "_phone": "555-123-4567",
        "_medical_record_number": "MRNTEST123",
        "_address_line1": "123 Mock St",
        # Add other PII fields that are simple strings and use EncryptedString/EncryptedText
        "_insurance_number": "INS-TEST-789"
    }

    # Define default raw JSON data (as dicts/lists before json.dumps and encryption)
    default_raw_json = {
        "_medical_history": [{"condition": "Mockitis", "diagnosed_date": "2020-01-01"}],
        "_medications": [{"name": "Mockacillin", "dosage": "500mg"}],
        "_allergies": [{"allergen": "Mocknuts", "reaction": "Hives"}],
        # "_emergency_contact": {"name": "EC Name", "phone": "555-5555", "relationship": "Friend"} # Assuming EncryptedJSON
    }

    current_raw_data = {**default_raw_pii, **default_raw_json}
    if raw_data_overrides:
        current_raw_data.update(raw_data_overrides)

    mock_model = PatientModel(id=patient_uuid) # Initialize with ID

    for field_name, raw_value in current_raw_data.items():
        if raw_value is None:
            setattr(mock_model, field_name, None)
            continue

        if field_name in default_raw_json: # Fields intended for EncryptedJSON
            # EncryptedJSON uses encrypt_string after json.dumps
            json_string = json.dumps(raw_value)
            encrypted_value = await mock_encrypt_service.encrypt_string(json_string)
            setattr(mock_model, field_name, encrypted_value)
        elif field_name in default_raw_pii and not isinstance(raw_value, date): # Simple string fields for EncryptedString/Text
            encrypted_value = await mock_encrypt_service.encrypt_string(str(raw_value))
            setattr(mock_model, field_name, encrypted_value)
        else: # Non-encrypted or already correct type (like _dob as date)
            setattr(mock_model, field_name, raw_value)
    
    # Set non-PII defaults
    mock_model.is_active = True
    mock_model.created_at = datetime.now(timezone.utc) - timedelta(days=1)
    mock_model.updated_at = datetime.now(timezone.utc)
    mock_model.version = 1

    return mock_model


@pytest.mark.asyncio
class TestPatientRepository:
    """Test suite for the SQLAlchemy implementation of PatientRepository."""
    
    @pytest.mark.asyncio
    async def test_init(self, patient_repository):
        """Test repository initialization."""
        assert patient_repository is not None
        assert hasattr(patient_repository, "db_session_factory")
        assert hasattr(patient_repository, "logger")
    
    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance') # Target the instance used by TypeDecorators
    async def test_get_by_id(self, mock_patient_module_esi: MagicMock, patient_repository: PatientRepository, mock_db_session: AsyncMock, sample_patient_id: str, mock_encryption_service: MagicMock, async_mock_patch: Any):
        """Test retrieving a patient by ID, ensuring decryption is handled by TypeDecorator via patched service."""
        # Configure the patched encryption_service_instance to be our mock_encryption_service
        mock_patient_module_esi.encrypt_string = mock_encryption_service.encrypt_string
        mock_patient_module_esi.decrypt_string = mock_encryption_service.decrypt_string

        patient_uuid = uuid.UUID(sample_patient_id)
        
        # 1. Define the raw data that we expect after decryption
        expected_raw_data = {
            "_first_name": "JohnOriginal",
            "_last_name": "DoeOriginal",
            "_email": "john.doe.original@example.com",
            "_dob": date(1980, 1, 1) # Date objects are not string-encrypted by our mock
        }

        # 2. Create a mock PatientModel instance with 'encrypted' data using the new helper
        # This simulates the model as it would be fetched from the DB
        mock_model_from_db = await create_mock_patient_model_with_encrypted_data(
            patient_id_str=sample_patient_id,
            mock_encrypt_service=mock_encryption_service,
            raw_data_overrides=expected_raw_data # Pass the plaintext here, helper encrypts relevant fields
        )
        # Ensure the ID is set correctly for assertion later
        mock_model_from_db.id = patient_uuid 

        # 3. Configure the mock DB session to return this model
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = mock_model_from_db

        # 4. Call the repository method
        retrieved_entity = await patient_repository.get_by_id(sample_patient_id)

        # 5. Assertions
        assert retrieved_entity is not None
        assert retrieved_entity.id == patient_uuid
        # Check that to_domain (via TypeDecorator) used the mock_decrypt_string to get original data
        assert retrieved_entity.first_name == expected_raw_data["_first_name"]
        assert retrieved_entity.last_name == expected_raw_data["_last_name"]
        assert retrieved_entity.email == expected_raw_data["_email"]
        assert retrieved_entity.date_of_birth == expected_raw_data["_dob"]

        # Verify that decrypt_string was called for each encrypted field that was overridden
        # The helper encrypts what's in default_raw_pii (and not a date) + default_raw_json.
        # If expected_raw_data overrides these, those are the values that get encrypted.
        
        # Get the 'encrypted' values that were set on mock_model_from_db for assertion
        # These assertions are more precise if we know which fields were encrypted by the helper
        encrypted_fn_on_model = mock_model_from_db._first_name 
        encrypted_ln_on_model = mock_model_from_db._last_name
        encrypted_email_on_model = mock_model_from_db._email

        mock_encryption_service.decrypt_string.assert_any_call(encrypted_fn_on_model)
        mock_encryption_service.decrypt_string.assert_any_call(encrypted_ln_on_model)
        mock_encryption_service.decrypt_string.assert_any_call(encrypted_email_on_model)

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, patient_repository: PatientRepository, mock_db_session: AsyncMock, sample_patient_id: str, async_mock_patch: Any):
        """Test get_by_id when patient is not found."""
        patient_uuid = uuid.UUID(sample_patient_id)
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = None

        entity = await patient_repository.get_by_id(sample_patient_id)

        mock_db_session.execute.assert_awaited_once()
        # Ensure the select statement was for the correct ID
        # This requires inspecting the call args of session.execute, which can be complex.
        # For now, trust the internal logic and focus on the outcome.
        assert entity is None

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.PatientModel', new_callable=MagicMock) # Mock the PatientModel class itself
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_create_patient(self, mock_patient_module_esi: MagicMock, MockPatientModelClass: MagicMock, patient_repository: PatientRepository, mock_db_session: AsyncMock, sample_patient_data: dict, mock_encryption_service: MagicMock, async_mock_patch: Any):
        """Test creating a patient, ensuring encryption is triggered and data is correctly returned."""
        # Configure the patched encryption_service_instance
        mock_patient_module_esi.encrypt_string = mock_encryption_service.encrypt_string
        mock_patient_module_esi.decrypt_string = mock_encryption_service.decrypt_string

        # 1. Prepare PatientEntity with raw data
        patient_entity_to_create = PatientEntity(**sample_patient_data)

        # 2. Configure the mock PatientModel class and its instances
        mock_created_model_instance = MagicMock(spec=PatientModel) # This is what from_domain will 'return' conceptually
        mock_refreshed_model_instance = MagicMock(spec=PatientModel) # This is after session.refresh
        
        # Mock PatientModel.from_domain classmethod
        # It should be an async method
        async def mock_from_domain(entity_arg): 
            # In a real scenario, from_domain copies data from entity_arg to mock_created_model_instance
            # For this test, we assume it correctly prepares mock_created_model_instance
            assert entity_arg == patient_entity_to_create
            # Simulate copying essential ID for refresh, etc.
            mock_created_model_instance.id = entity_arg.id 
            # Allow other attributes to be set on mock_created_model_instance if needed for assertion before refresh
            return mock_created_model_instance
        MockPatientModelClass.from_domain = AsyncMock(side_effect=mock_from_domain)

        # Configure mock_created_model_instance to represent the state before refresh
        # Its PII attributes would be plaintext copied by from_domain, ready for TypeDecorator
        mock_created_model_instance.id = patient_entity_to_create.id
        mock_created_model_instance._first_name = patient_entity_to_create.first_name
        mock_created_model_instance._last_name = patient_entity_to_create.last_name
        mock_created_model_instance._email = patient_entity_to_create.email
        mock_created_model_instance._dob = patient_entity_to_create.date_of_birth # dob is date object

        # Configure the mock_refreshed_model_instance (after potential DB changes/encryption)
        # Its PII attributes should be the 'encrypted' versions
        mock_refreshed_model_instance.id = patient_entity_to_create.id
        mock_refreshed_model_instance._first_name = await mock_encryption_service.encrypt_string(patient_entity_to_create.first_name)
        mock_refreshed_model_instance._last_name = await mock_encryption_service.encrypt_string(patient_entity_to_create.last_name)
        mock_refreshed_model_instance._email = await mock_encryption_service.encrypt_string(patient_entity_to_create.email)
        mock_refreshed_model_instance._dob = patient_entity_to_create.date_of_birth # dob is date object, not encrypted by string encryptor
        mock_refreshed_model_instance.is_active = True # Assuming default
        mock_refreshed_model_instance.created_at = datetime.now(timezone.utc)
        mock_refreshed_model_instance.updated_at = datetime.now(timezone.utc)

        # Mock session.refresh to make patient_model become mock_refreshed_model_instance
        async def mock_refresh(target_model):
            assert target_model == mock_created_model_instance
            # Simulate refresh by copying attributes from the 'refreshed' state
            for attr in dir(mock_refreshed_model_instance):
                if not attr.startswith('__') and not callable(getattr(mock_refreshed_model_instance, attr)):
                    setattr(target_model, attr, getattr(mock_refreshed_model_instance, attr))
            return
        mock_db_session.refresh = AsyncMock(side_effect=mock_refresh)
        
        # Mock the to_domain method of the *refreshed* model instance
        # This to_domain will be called at the end of repository.create()
        async def mock_to_domain_on_refreshed():
            # This simulates TypeDecorators using the (patched) decrypt_string
            return PatientEntity(
                id=mock_refreshed_model_instance.id,
                first_name=await mock_encryption_service.decrypt_string(mock_refreshed_model_instance._first_name),
                last_name=await mock_encryption_service.decrypt_string(mock_refreshed_model_instance._last_name),
                email=await mock_encryption_service.decrypt_string(mock_refreshed_model_instance._email),
                date_of_birth=mock_refreshed_model_instance._dob,
                medical_record_number=patient_entity_to_create.medical_record_number, # Assuming not changed/encrypted for this test focus
                is_active=mock_refreshed_model_instance.is_active,
                created_at=mock_refreshed_model_instance.created_at,
                updated_at=mock_refreshed_model_instance.updated_at
            )
        mock_created_model_instance.to_domain = AsyncMock(side_effect=mock_to_domain_on_refreshed) # to_domain is on instance from_domain returns

        # 3. Call the repository method
        created_entity = await patient_repository.create(patient_entity_to_create)

        # 4. Assertions
        MockPatientModelClass.from_domain.assert_awaited_once_with(patient_entity_to_create)
        mock_db_session.add.assert_called_once_with(mock_created_model_instance)
        mock_db_session.flush.assert_awaited_once()
        mock_db_session.refresh.assert_awaited_once_with(mock_created_model_instance)
        mock_created_model_instance.to_domain.assert_awaited_once()

        assert created_entity is not None
        assert created_entity.id == patient_entity_to_create.id
        assert created_entity.first_name == patient_entity_to_create.first_name # Decrypted
        assert created_entity.last_name == patient_entity_to_create.last_name   # Decrypted
        assert created_entity.email == patient_entity_to_create.email         # Decrypted

        # Verify that encrypt_string was called by TypeDecorators via SQLAlchemy's flush processing
        # This is an indirect check. The TypeDecorator on PatientModel._first_name would have called it.
        # We assume SQLAlchemy calls process_bind_param on flush for new instances.
        mock_encryption_service.encrypt_string.assert_any_call(patient_entity_to_create.first_name)
        mock_encryption_service.encrypt_string.assert_any_call(patient_entity_to_create.last_name)
        mock_encryption_service.encrypt_string.assert_any_call(patient_entity_to_create.email)

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.PatientModel', new_callable=MagicMock) # For mocking from_domain
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_update_patient(self, mock_patient_module_esi: MagicMock, MockPatientModelClass: MagicMock, patient_repository: PatientRepository, mock_db_session: AsyncMock, sample_patient_id: str, mock_encryption_service: MagicMock, async_mock_patch: Any):
        """Test updating a patient, ensuring encryption and decryption flows."""
        # 1. Configure Patched Services & Mocks
        mock_patient_module_esi.encrypt_string = mock_encryption_service.encrypt_string
        mock_patient_module_esi.decrypt_string = mock_encryption_service.decrypt_string

        patient_uuid = uuid.UUID(sample_patient_id)

        # 2. Data for Update
        # This is the entity with *new plaintext data* that we want to update with
        update_entity_data = PatientEntity(
            id=patient_uuid,
            first_name="JaneUpdated",
            last_name="DoeUpdated",
            email="jane.doe.updated@example.com",
            date_of_birth=date(1985, 5, 5),
            medical_record_number="MRN_UPDATED_789"
        )

        # 3. Mock Existing Model in DB (pre-update state)
        # This model has 'old encrypted' data. We'll use the helper for this.
        # Define the raw data that corresponds to this pre-update 'encrypted' model
        raw_data_for_pre_update_model = {
            "_first_name": "JohnOriginal", # Original name before update
            "_last_name": "DoeOriginal",
            "_email": "john.original@example.com",
            "_dob": date(1980,1,1) # Original DOB
        }
        existing_model_from_db = await create_mock_patient_model_with_encrypted_data(
            patient_id_str=sample_patient_id,
            mock_encrypt_service=mock_encryption_service,
            raw_data_overrides=raw_data_for_pre_update_model
        )
        existing_model_from_db.id = patient_uuid # Ensure ID is correct

        # Configure session.execute to return this existing_model_from_db on fetch
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = existing_model_from_db

        # 4. Mock the to_domain method of the existing_model_from_db (which will be updated)
        # This will be called at the end of repository.update() to return the final entity.
        # It should reflect the *updated and then decrypted* data.
        async def mock_to_domain_on_updated_model(): 
            # This simulates TypeDecorators using decrypt_string on the *updated* (mock-encrypted) attributes
            # The attributes on existing_model_from_db will be updated in-place by setattr in the repo.
            # So, we decrypt those current values from existing_model_from_db.
            return PatientEntity(
                id=existing_model_from_db.id,
                first_name=await mock_encryption_service.decrypt_string(existing_model_from_db._first_name),
                last_name=await mock_encryption_service.decrypt_string(existing_model_from_db._last_name),
                email=await mock_encryption_service.decrypt_string(existing_model_from_db._email),
                date_of_birth=existing_model_from_db._dob, # Date objects aren't string-encrypted
                medical_record_number=update_entity_data.medical_record_number, # Assume this field was also updated
                is_active=getattr(existing_model_from_db, 'is_active', True),
                created_at=getattr(existing_model_from_db, 'created_at', datetime.now(timezone.utc)),
                updated_at=getattr(existing_model_from_db, 'updated_at', datetime.now(timezone.utc))
            )
        # The model instance fetched from DB is the one whose to_domain is called.
        existing_model_from_db.to_domain = AsyncMock(side_effect=mock_to_domain_on_updated_model)

        # 5. Call Repository Method
        updated_entity = await patient_repository.update(update_entity_data)

        # 6. Assertions
        # Check the initial fetch
        mock_db_session.execute.assert_awaited_once() 
        # Add more specific check for select statement if necessary

        # Check setattr calls on existing_model_from_db (indirectly checks TypeDecorator for encryption)
        # SQLAlchemy's flush will trigger process_bind_param which uses encrypt_string.
        mock_encryption_service.encrypt_string.assert_any_call(update_entity_data.first_name)
        mock_encryption_service.encrypt_string.assert_any_call(update_entity_data.last_name)
        mock_encryption_service.encrypt_string.assert_any_call(update_entity_data.email)
        # dob is not string-encrypted, medical_record_number is assumed handled by EncryptedString if _prefixed
        if hasattr(update_entity_data, 'medical_record_number') and update_entity_data.medical_record_number:
             # Assuming _medical_record_number is an EncryptedString field in PatientModel
            mock_encryption_service.encrypt_string.assert_any_call(update_entity_data.medical_record_number)

        mock_db_session.flush.assert_awaited_once()
        mock_db_session.refresh.assert_awaited_once_with(existing_model_from_db)
        existing_model_from_db.to_domain.assert_awaited_once()

        assert updated_entity is not None
        assert updated_entity.id == patient_uuid
        assert updated_entity.first_name == update_entity_data.first_name # Check final decrypted data
        assert updated_entity.last_name == update_entity_data.last_name
        assert updated_entity.email == update_entity_data.email
        assert updated_entity.date_of_birth == update_entity_data.date_of_birth

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_get_all_patients(self, mock_patient_module_esi: MagicMock, patient_repository: PatientRepository, mock_db_session: AsyncMock, mock_encryption_service: MagicMock, async_mock_patch: Any):
        """Test retrieving all patients with pagination, ensuring decryption."""
        # 1. Configure Patched Service
        mock_patient_module_esi.encrypt_string = mock_encryption_service.encrypt_string
        mock_patient_module_esi.decrypt_string = mock_encryption_service.decrypt_string

        # 2. Prepare multiple mock PatientModel instances with 'encrypted' data
        patient_id_1 = str(uuid.uuid4())
        raw_data_1 = {"_first_name": "Alice", "_email": "alice@example.com"}
        model_1 = await create_mock_patient_model_with_encrypted_data(
            patient_id_str=patient_id_1, 
            mock_encrypt_service=mock_encryption_service, 
            raw_data_overrides=raw_data_1
        )
        model_1.id = uuid.UUID(patient_id_1) # Ensure ID is UUID

        patient_id_2 = str(uuid.uuid4())
        raw_data_2 = {"_first_name": "Bob", "_email": "bob@example.com"}
        model_2 = await create_mock_patient_model_with_encrypted_data(
            patient_id_str=patient_id_2, 
            mock_encrypt_service=mock_encryption_service, 
            raw_data_overrides=raw_data_2
        )
        model_2.id = uuid.UUID(patient_id_2)

        mock_models_from_db = [model_1, model_2]

        # 3. Configure mock DB session to return these models
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_models_from_db

        # 4. Call repository method
        retrieved_entities = await patient_repository.get_all(limit=10, offset=0)

        # 5. Assertions
        assert len(retrieved_entities) == 2
        mock_db_session.execute.assert_awaited_once() # Should be called for select

        # Check data for Alice (model_1)
        entity_1 = next(e for e in retrieved_entities if e.id == model_1.id)
        assert entity_1.first_name == raw_data_1["_first_name"]
        assert entity_1.email == raw_data_1["_email"]
        mock_encryption_service.decrypt_string.assert_any_call(model_1._first_name)
        mock_encryption_service.decrypt_string.assert_any_call(model_1._email)

        # Check data for Bob (model_2)
        entity_2 = next(e for e in retrieved_entities if e.id == model_2.id)
        assert entity_2.first_name == raw_data_2["_first_name"]
        assert entity_2.email == raw_data_2["_email"]
        mock_encryption_service.decrypt_string.assert_any_call(model_2._first_name)
        mock_encryption_service.decrypt_string.assert_any_call(model_2._email)
        
        # Total decrypt calls should be for all encrypted fields from all models
        # Assuming 2 encrypted fields per model here for simplicity (first_name, email)
        # This count might need adjustment based on how many fields create_mock_patient_model_with_encrypted_data actually encrypts
        # For more robustness, count calls per unique encrypted string if possible, or track calls more granularly.
        # Total calls will be at least 4 (2 fields * 2 patients for the overridden fields)
        # plus any other fields the helper encrypts by default.
        assert mock_encryption_service.decrypt_string.call_count >= 4 

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance')
    async def test_get_by_email(self, mock_patient_module_esi: MagicMock, patient_repository: PatientRepository, mock_db_session: AsyncMock, mock_encryption_service: MagicMock, async_mock_patch: Any):
        """Test retrieving a patient by email, ensuring decryption."""
        # 1. Configure Patched Service
        mock_patient_module_esi.encrypt_string = mock_encryption_service.encrypt_string
        mock_patient_module_esi.decrypt_string = mock_encryption_service.decrypt_string

        # 2. Prepare mock PatientModel with 'encrypted' data
        target_email_raw = "find.me@example.com"
        patient_id_for_email_test = str(uuid.uuid4())
        
        # The model should have the email field encrypted with the target_email_raw
        # Other fields can use defaults from the helper or be overridden if needed for the entity construction
        raw_data_for_model = {
            "_email": target_email_raw, 
            "_first_name": "EmailUser"
        }
        model_from_db = await create_mock_patient_model_with_encrypted_data(
            patient_id_str=patient_id_for_email_test,
            mock_encrypt_service=mock_encryption_service,
            raw_data_overrides=raw_data_for_model
        )
        model_from_db.id = uuid.UUID(patient_id_for_email_test)

        # 3. Configure mock DB session 
        # The repository encrypts the email before querying, so the mock query needs to expect the encrypted form.
        encrypted_target_email = await mock_encryption_service.encrypt_string(target_email_raw)
        
        # We need to ensure that when session.execute is called with a select statement
        # that filters on PatientModel._email == encrypted_target_email, it returns model_from_db.
        # This is tricky to mock perfectly without deeper inspection of the select statement object.
        # For simplicity, we'll assume the execute call for get_by_email, if it finds a match, returns the model.
        # A more robust mock would inspect the actual query.
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = model_from_db

        # 4. Call repository method
        retrieved_entity = await patient_repository.get_by_email(target_email_raw)

        # 5. Assertions
        assert retrieved_entity is not None
        assert retrieved_entity.id == model_from_db.id
        assert retrieved_entity.email == target_email_raw # Ensure decrypted email matches
        assert retrieved_entity.first_name == raw_data_for_model["_first_name"] # Check other decrypted field

        mock_db_session.execute.assert_awaited_once() # Verify DB was queried
        
        # Verify decryption calls for the fields on the retrieved model
        mock_encryption_service.decrypt_string.assert_any_call(model_from_db._email)
        mock_encryption_service.decrypt_string.assert_any_call(model_from_db._first_name)

    @pytest.mark.asyncio
    async def test_delete_patient_success(self, patient_repository: PatientRepository, mock_db_session: AsyncMock, sample_patient_id: str, async_mock_patch: Any):
        """Test successfully deleting a patient."""
        patient_uuid = uuid.UUID(sample_patient_id)

        # Mock the model to be returned by session.get (or equivalent select for delete target)
        mock_patient_to_delete = PatientModel(id=patient_uuid)
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = mock_patient_to_delete 
        # If delete directly uses session.get, then:
        # mock_db_session.get.return_value = mock_patient_to_delete

        # mock_db_session.delete is an AsyncMock
        mock_db_session.delete.return_value = None # delete doesn't usually return a value
        mock_db_session.flush.return_value = None 

        result = await patient_repository.delete(sample_patient_id)

        assert result is True
        # Verify the correct model was targeted for deletion by select first
        mock_db_session.execute.assert_awaited_once() 
        # Add specific check for select statement for patient_uuid if possible
        
        mock_db_session.delete.assert_awaited_once_with(mock_patient_to_delete)
        mock_db_session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_patient_not_found(self, patient_repository: PatientRepository, mock_db_session: AsyncMock, sample_patient_id: str, async_mock_patch: Any):
        """Test deleting a patient that is not found."""
        patient_uuid = uuid.UUID(sample_patient_id)
        
        # Mock session.execute to find no patient
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = None
        # If delete directly uses session.get, then:
        # mock_db_session.get.return_value = None

        result = await patient_repository.delete(sample_patient_id)

        assert result is False
        mock_db_session.execute.assert_awaited_once()
        mock_db_session.delete.assert_not_called() # Delete should not be called if patient not found
        mock_db_session.flush.assert_not_called()

    # TODO: Test error/edge cases for all methods

# Further tests would go here, e.g., for update, delete, error conditions.
