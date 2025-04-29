# -*- coding: utf-8 -*-
"""Unit tests for the Patient repository SQLAlchemy implementation.

This module tests the functionality of the PatientRepository class to ensure
that it correctly interacts with the database layer, properly handling
patient data in accordance with HIPAA and other security requirements.
"""

import asyncio
import pytest
import json
import uuid
import types
from unittest.mock import AsyncMock, MagicMock, patch, call
from datetime import datetime, timedelta, timezone, date
from typing import Dict, Any, Optional, List
import base64
import binascii
import logging
from faker import Faker

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Column, String, select
from sqlalchemy.exc import SQLAlchemyError

from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import PatientRepository
from app.domain.entities.patient import Patient as PatientEntity
from app.domain.entities.patient import Patient as PatientDomain
from app.infrastructure.persistence.sqlalchemy.models.patient import Patient as PatientModel
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from app.core.exceptions import PersistenceError

@pytest.fixture
def sample_patient_id() -> str:
    """Return a consistent UUID for testing."""
    return "12345678-1234-5678-1234-567812345678"


@pytest.fixture
def sample_patient_data(sample_patient_id: str) -> Dict[str, Any]:
    """Create sample patient data for testing."""
    return {
        "id": sample_patient_id,
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1980-01-01",
        "medical_record_number": "MRN12345",
        "email": "john.doe@example.com"
    }


@pytest.fixture
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
    """Fixture to create a mock encryption service with base64 encoding/decoding."""
    mock_service = MagicMock(spec=BaseEncryptionService)

    async def mock_encrypt(raw_data: str) -> bytes:
        """Simulate encryption: string -> utf8 bytes -> base64 bytes."""
        if not isinstance(raw_data, str):
            # Ensure input is string as expected by the calling repository code
            raise TypeError(f"Mock encryption needs string input. Got {type(raw_data).__name__}")
        try:
            data_bytes = raw_data.encode('utf-8')
            encrypted_bytes = base64.b64encode(data_bytes)
            return encrypted_bytes
        except Exception as e:
            logging.error(f"Mock encryption error: {e}")
            raise

    async def mock_decrypt(encrypted_data: bytes) -> bytes:
        """Simulate decryption: base64 bytes -> utf8 bytes."""
        if not isinstance(encrypted_data, bytes):
            # Ensure input is bytes as expected
            raise TypeError(f"Mock decryption needs bytes input. Got {type(encrypted_data).__name__}")
        try:
            decrypted_bytes = base64.b64decode(encrypted_data)
            return decrypted_bytes
        except Exception as e:
            logging.error(f"Mock decryption error: {e}")
            raise

    # Use AsyncMock for the async methods encrypt and decrypt
    mock_service.encrypt = AsyncMock(side_effect=mock_encrypt)
    mock_service.decrypt = AsyncMock(side_effect=mock_decrypt)

    return mock_service


@pytest.fixture
def patient_repository(mock_db_session, mock_encryption_service) -> PatientRepository: 
    """Create a PatientRepository instance for testing, providing a mock session factory and encryption service."""
    # Create a mock factory function/object
    mock_session_factory = MagicMock() # Use MagicMock for a simple callable

    # Configure the factory to return the mock_db_session when called
    mock_session_factory.return_value = mock_db_session

    # Pass the FACTORY and the mock service to the repository constructor
    return PatientRepository(db_session_factory=mock_session_factory,
                             encryption_service=mock_encryption_service,
                             user_context={"user_id": "test-user"})


# Helper to create mock PatientModel instances with consistent encrypted data
async def create_mock_patient_model(
    patient_id: str,
    mock_encrypt_service: AsyncMock,
    **kwargs  # Accept arbitrary keyword arguments
) -> tuple[PatientModel, dict]:
    """Creates a mock PatientModel instance and its raw (unencrypted) data.

    Args:
        patient_id: The ID for the mock patient.
        mock_encrypt_service: The mock encryption service.
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
    sensitive_fields = PatientRepository.sensitive_field_map.values()
    json_fields_entity = PatientRepository.json_fields_entity

    for field, value in raw_data.items():
        if field in sensitive_fields:
            # Use the provided mock encrypt service
            original_value = str(value) # Ensure string for encryption
            encrypted_bytes = await mock_encrypt_service.encrypt(original_value)
            setattr(mock_model, field, encrypted_bytes) # Store as bytes in model
        elif isinstance(value, (datetime, date)):
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
    async def test_init(self, patient_repository, mock_encryption_service): 
        """Test repository initialization."""
        assert patient_repository is not None
        assert hasattr(patient_repository, "db_session_factory")
        assert "ssn" in patient_repository.sensitive_field_map
        assert "_ssn" == patient_repository.sensitive_field_map["ssn"]
        # Check if the *mock* encryption service is assigned
        assert patient_repository.encryption_service is mock_encryption_service
    
    @pytest.mark.asyncio
    async def test_get_by_id(self, patient_repository, mock_db_session, sample_patient_id, mock_encryption_service, async_mock_patch):
        """Test get_by_id retrieves and converts a patient model."""
        # 1. Arrange
        patient_uuid = uuid.UUID(sample_patient_id)
        
        # Create a sample patient entity for the mock method to return
        expected_entity = PatientEntity(
            id=patient_uuid,
            first_name="John",
            last_name="Doe",
            date_of_birth="1980-01-01",
            email="john.doe@example.com"
        )
        
        # Create a simple PatientModel instance with underscored field names
        mock_model = PatientModel()
        mock_model.id = patient_uuid
        mock_model._first_name = await mock_encryption_service.encrypt("John")
        mock_model._last_name = await mock_encryption_service.encrypt("Doe")
        mock_model._dob = datetime(1980, 1, 1).date()
        mock_model._email = await mock_encryption_service.encrypt("john.doe@example.com")
        
        # Configure the session.get to return our mock model
        mock_db_session.get.return_value = mock_model
        
        # Mock the _convert_to_domain method to return our expected entity
        original_convert = patient_repository._convert_to_domain
        
        async def mock_convert_to_domain(model):
            assert model is mock_model
            return expected_entity
            
        patient_repository._convert_to_domain = mock_convert_to_domain
        
        try:
            # 2. Act
            patient_entity = await patient_repository.get_by_id(sample_patient_id)
            
            # 3. Assert
            # Verify session.get was called correctly
            mock_db_session.get.assert_awaited_once_with(PatientModel, patient_uuid)
            
            # Verify basic properties of returned entity
            assert patient_entity is not None
            assert patient_entity is expected_entity
            assert str(patient_entity.id) == sample_patient_id
            assert patient_entity.first_name == "John"
            assert patient_entity.last_name == "Doe"
        finally:
            # Restore original method
            patient_repository._convert_to_domain = original_convert
    
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
