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


# Helper to create mock PatientModel instances with consistent encrypted data
async def create_mock_patient_model(
    patient_id: str,
    **kwargs  # Accept arbitrary keyword arguments
) -> tuple[PatientModel, dict]:
    """Creates a mock PatientModel instance and its raw (unencrypted) data.

    Args:
        patient_id: The ID for the mock patient.
        **kwargs: Additional attributes to set on the mock model.

    Returns:
        A tuple containing the mock PatientModel instance and a dictionary of the
        original, unencrypted data used to create it.
    """
    # 1. Define raw data
    raw_data = {
        "id": uuid.UUID(patient_id),
        "_first_name": "TestFirstName",
        "_last_name": "TestLastName",
        "_ssn": "999-99-9999",
        "_dob": date(1990, 1, 1),
        "_email": "test.patient@example.com",
        "_phone": "555-123-4567",
        "_address_line1": "123 Mock St",
        "_address_line2": "Apt 4B",
        "_city": "Mockville",
        "_state": "MS",
        "_postal_code": "12345",
        "_country": "Mockland",
        "_emergency_contact_name": "Mock Contact",
        "_emergency_contact_phone": "555-987-6543",
        "_emergency_contact_relationship": "Friend",
        "_insurance_provider": "Mock Insurance Co.",
        "_insurance_policy_number": "MOCK123456",
        "_insurance_group_number": "GROUPMOCK",
        "_preferred_pharmacy": "Mock Pharmacy",
        "_primary_care_physician": "Dr. Mock",
        "_medical_history": json.dumps([{"condition": "Mockitis", "diagnosed_date": "2020-01-01"}]),
        "_medications": json.dumps([{"name": "Mockacillin", "dosage": "500mg"}]),
        "_allergies": json.dumps([{"allergen": "Mocknuts", "reaction": "Hives"}]),
        "_treatment_notes": json.dumps([{"date": "2023-01-15", "note": "Patient feels mocky."}]),
        "created_at": datetime.now(timezone.utc) - timedelta(days=1),
        "updated_at": datetime.now(timezone.utc),
        "version": 1,
        "_extra_data": json.dumps({"mock_key": "mock_value"})
    }

    # Apply kwargs to raw_data before encryption/model creation
    for key, value in kwargs.items():
        # Need to map kwarg name (e.g., 'first_name') to raw_data key ('_first_name')
        model_key = f"_{key}" # Simple assumption for this mock
        if model_key in raw_data:
            raw_data[model_key] = value
        elif key == 'id': # Handle id separately if passed
            raw_data['id'] = uuid.UUID(value) if isinstance(value, str) else value
        # Add more specific mappings if needed

    # 2. Create the model instance
    mock_model = PatientModel()

    # 3. Apply raw data, encrypting sensitive fields
    for field, value in raw_data.items():
        if isinstance(value, (datetime, date)):
             setattr(mock_model, field, value) # Keep date/datetime objects as is for model
        elif field not in ['created_at', 'updated_at']: # Avoid overwriting automatic timestamps
             setattr(mock_model, field, value)

    # Set timestamps directly if needed for specific test scenario
    mock_model.created_at = raw_data['created_at']
    mock_model.updated_at = raw_data['updated_at']

    return mock_model, raw_data


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
        mock_patient_module_esi.return_value = mock_encryption_service # If esi were a callable factory
        # If encryption_service_instance is a direct instance, we assign methods or the whole mock:
        mock_patient_module_esi.encrypt_string = mock_encryption_service.encrypt_string
        mock_patient_module_esi.decrypt_string = mock_encryption_service.decrypt_string
        # Add other methods like encrypt_dict, decrypt_dict if EncryptedJSON uses them directly from the service instance

        patient_uuid = uuid.UUID(sample_patient_id)
        
        # 1. Prepare raw data and its 'encrypted' form using the mock service
        raw_first_name = "John"
        raw_last_name = "Doe"
        raw_email = "john.doe@example.com"

        encrypted_first_name = await mock_encryption_service.encrypt_string(raw_first_name)
        encrypted_last_name = await mock_encryption_service.encrypt_string(raw_last_name)
        encrypted_email = await mock_encryption_service.encrypt_string(raw_email)

        # 2. Create a mock PatientModel instance with 'encrypted' data
        # This is what the repository would receive from the database
        mock_model_from_db = PatientModel(
            id=patient_uuid,
            _first_name=encrypted_first_name,
            _last_name=encrypted_last_name,
            _dob=date(1980, 1, 1),
            _email=encrypted_email,
            # ... other fields can be None or have non-encrypted mock values ...
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        # 3. Configure the mock DB session to return this model
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = mock_model_from_db

        # 4. Call the repository method
        retrieved_entity = await patient_repository.get_by_id(sample_patient_id)

        # 5. Assertions
        assert retrieved_entity is not None
        assert retrieved_entity.id == patient_uuid
        # Check that to_domain (via TypeDecorator) used the mock_decrypt_string
        assert retrieved_entity.first_name == raw_first_name
        assert retrieved_entity.last_name == raw_last_name
        assert retrieved_entity.email == raw_email
        assert retrieved_entity.date_of_birth == date(1980, 1, 1)

        # Verify that decrypt_string was called for each encrypted field
        mock_encryption_service.decrypt_string.assert_any_call(encrypted_first_name)
        mock_encryption_service.decrypt_string.assert_any_call(encrypted_last_name)
        mock_encryption_service.decrypt_string.assert_any_call(encrypted_email)
        # Check call count if necessary, e.g., assert mock_encryption_service.decrypt_string.call_count == 3 (or more if other fields were encrypted)

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, patient_repository, mock_db_session, sample_patient_id, async_mock_patch):
        """Test get_by_id returns None when patient not found."""
        # 1. Arrange - Configure session.get to return None for not found
        mock_db_session.get.return_value = None
        
        # 2. Act
        result = await patient_repository.get_by_id(sample_patient_id)
        
        # 3. Assert
        assert result is None
        # Verify session.get was called correctly
        mock_db_session.get.assert_awaited_once()
