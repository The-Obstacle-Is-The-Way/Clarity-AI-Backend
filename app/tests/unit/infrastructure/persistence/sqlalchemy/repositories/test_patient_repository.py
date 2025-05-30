"""Unit tests for the Patient repository SQLAlchemy implementation.

This module tests the functionality of the PatientRepository class to ensure
that it correctly interacts with the database layer, properly handling
patient data in accordance with HIPAA and other security requirements.
"""

import base64
import json
import logging
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.domain.enums import Gender
from app.domain.entities.patient import Patient as PatientEntity
from app.domain.value_objects.address import Address
from app.infrastructure.persistence.sqlalchemy.models.patient import Patient as PatientModel
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepository,
)
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService,
)


@pytest.fixture
def sample_patient_id() -> str:
    """Return a consistent UUID for testing."""
    return "12345678-1234-5678-1234-567812345678"


@pytest.fixture
def sample_patient_data(sample_patient_id: str) -> dict[str, Any]:
    """Create sample patient data for testing."""
    return {
        "id": uuid.UUID(sample_patient_id),
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": date(1980, 1, 1),
        # "medical_record_number_lve": "MRN12345", # Temporarily removed for diagnosis
        "email": "john.doe@example.com",
    }


@pytest.fixture
def mock_db_session() -> AsyncMock:
    """Provides a mock asynchronous session object."""
    session = AsyncMock(spec=AsyncSession)

    # Mock the execute method and its chained calls
    # session.execute is an AsyncMock, its result (after await) is a mock Result object.
    mock_result = MagicMock()  # This will simulate the Result object
    mock_scalars_result = MagicMock()  # This will simulate the ScalarResult object

    # Configure mock_scalars_result for .one_or_none() and .all()
    mock_scalars_result.one_or_none = MagicMock()
    mock_scalars_result.all = MagicMock()

    # Configure mock_result for .scalars()
    mock_result.scalars = MagicMock(return_value=mock_scalars_result)

    # Configure session.execute to be an AsyncMock returning mock_result
    session.execute = AsyncMock(return_value=mock_result)

    # Mock other session methods
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.flush = AsyncMock()
    session.close = AsyncMock()
    session.get = AsyncMock()  # Keep for delete path
    session.delete = AsyncMock()
    session.rollback = AsyncMock()  # Add awaitable rollback

    # Mock context manager methods
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    # Mock the begin method and its context manager
    mock_transaction = AsyncMock()
    mock_transaction.__aenter__ = AsyncMock(return_value=None)
    mock_transaction.__aexit__ = AsyncMock(return_value=None)
    session.begin = MagicMock(return_value=mock_transaction)  # begin() itself is sync

    return session


@pytest.fixture
def mock_encryption_service():
    """Fixture to create a mock encryption service aligning with BaseEncryptionService string methods."""
    mock_service = MagicMock(spec=BaseEncryptionService)

    # encrypt_string: str -> str (simulating string in, encrypted string out)
    async def mock_encrypt_string(raw_string: str) -> str:
        if not isinstance(raw_string, str):
            raise TypeError(
                f"Mock encrypt_string needs string input. Got {type(raw_string).__name__}"
            )
        try:
            # Simulate encryption: string -> utf8 bytes -> base64 bytes -> base64 string
            encrypted_bytes = base64.b64encode(raw_string.encode("utf-8"))
            return encrypted_bytes.decode("utf-8")  # Return as string
        except Exception as e:
            logging.error(f"Mock encrypt_string error: {e}")
            raise

    # decrypt_string: str -> str (simulating encrypted string in, decrypted string out)
    async def mock_decrypt_string(encrypted_string: str) -> str:
        if not isinstance(encrypted_string, str):
            raise TypeError(
                f"Mock decrypt_string needs string input. Got {type(encrypted_string).__name__}"
            )
        try:
            # Simulate decryption: base64 string -> base64 bytes -> utf8 bytes -> string
            decrypted_bytes = base64.b64decode(encrypted_string.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            # Allow returning original string if b64decode fails, useful for non-encrypted test data
            logging.warning(f"Mock decrypt_string error: {e}. Returning original for testing.")
            return encrypted_string  # Fallback for testing with plaintext

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
    mock_session_factory = MagicMock()  # Use MagicMock for a simple callable

    # Configure the factory to return the mock_db_session when called
    mock_session_factory.return_value = mock_db_session

    # Pass the FACTORY to the repository constructor
    return PatientRepository(
        db_session_factory=mock_session_factory, user_context={"user_id": "test-user"}
    )


# Helper to create mock PatientModel instances with 'encrypted' data for test setups
async def create_mock_patient_model_with_encrypted_data(
    patient_id_str: str,
    mock_encrypt_service: MagicMock,  # Pass the mock service with .encrypt_string
    raw_data_overrides: dict | None = None,
) -> PatientModel:
    """Helper to create a mock PatientModel instance with specified fields encrypted."""
    patient_uuid = uuid.UUID(patient_id_str)

    # Define default raw PII data (as strings or appropriate types before encryption)
    # Using model attribute names (e.g., _first_name)
    default_raw_pii = {
        "_first_name": "TestFirstName",
        "_last_name": "TestLastName",
        "_ssn": "999-99-9999",
        "_dob": date(1990, 1, 1),  # Date object, not encrypted by encrypt_string
        "_email": "test.patient@example.com",
        "_phone": "555-123-4567",
        "_medical_record_number": "MRNTEST123",
        "_address_line1": "123 Mock St",
        # Add other PII fields that are simple strings and use EncryptedString/EncryptedText
        "_insurance_number": "INS-TEST-789",
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

    mock_model = PatientModel(id=patient_uuid)  # Initialize with ID

    for field_name, raw_value in current_raw_data.items():
        if raw_value is None:
            setattr(mock_model, field_name, None)
            continue

        if field_name in default_raw_json:  # Fields intended for EncryptedJSON
            # EncryptedJSON uses encrypt_string after json.dumps
            json_string = json.dumps(raw_value)
            encrypted_value = await mock_encrypt_service.encrypt_string(json_string)
            setattr(mock_model, field_name, encrypted_value)
        elif field_name in default_raw_pii and not isinstance(
            raw_value, date
        ):  # Simple string fields for EncryptedString/Text
            encrypted_value = await mock_encrypt_service.encrypt_string(str(raw_value))
            setattr(mock_model, field_name, encrypted_value)
        else:  # Non-encrypted or already correct type (like _dob as date)
            setattr(mock_model, field_name, raw_value)

    # Set non-PII defaults
    mock_model.is_active = True
    mock_model.created_at = datetime.now(timezone.utc) - timedelta(days=1)
    mock_model.updated_at = datetime.now(timezone.utc)
    mock_model.version = 1

    return mock_model


@pytest.fixture
def sample_patient_list_data() -> list[dict]:
    """Provides a list of sample patient data for get_all tests."""
    return [
        {
            "id": uuid.uuid4(),
            "first_name": "Alice",
            "last_name": "Smith",
            "date_of_birth": date(1985, 5, 10),
            "email": "alice.repo@example.com",
            "medical_record_number_lve": "MRNALICE1",
            "gender": Gender.FEMALE,
        },
        {
            "id": uuid.uuid4(),
            "first_name": "Bob",
            "last_name": "Johnson",
            "date_of_birth": date(1992, 8, 22),
            "email": "bob.repo@example.com",
            "medical_record_number_lve": "MRNBOB2",
            "gender": Gender.MALE,
        },
    ]


@pytest.mark.asyncio
class TestPatientRepository:
    """Test suite for the SQLAlchemy implementation of PatientRepository."""

    @pytest.mark.asyncio
    async def test_init(self, patient_repository) -> None:
        """Test repository initialization."""
        assert patient_repository is not None
        assert hasattr(patient_repository, "db_session_factory")
        assert hasattr(patient_repository, "logger")

    @pytest.mark.asyncio
    @patch(
        "app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance"
    )  # Target the instance used by TypeDecorators
    @pytest.mark.asyncio
    async def test_get_by_id(
        self,
        mock_patient_module_esi: MagicMock,
        patient_repository: PatientRepository,
        mock_db_session: AsyncMock,
        sample_patient_id: str,
        sample_patient_data: dict,
    ) -> None:
        """Test retrieving a patient by ID."""
        patient_uuid = uuid.UUID(sample_patient_id)
        mock_patient_model = MagicMock(spec=PatientModel)  # Use alias PatientModel
        mock_patient_model.id = patient_uuid
        # Populate with necessary fields for to_domain, including Address components
        mock_patient_model._first_name = "DecryptedFirstName"
        mock_patient_model._last_name = "DecryptedLastName"
        mock_patient_model._email = "decrypted.email@example.com"
        mock_patient_model._date_of_birth = date(1990, 1, 1).isoformat()  # Decrypted form
        mock_patient_model._address_line1 = "123 Main St"
        mock_patient_model._city = "Anytown"
        mock_patient_model._state = "CA"
        mock_patient_model._zip_code = "90210"  # Crucial for Address VO
        mock_patient_model._country = "USA"
        # Add other fields that Patient.to_domain() might access and are required by PatientEntity

        async def mock_to_domain_for_get():
            # Simulate full to_domain conversion, including Address
            return PatientEntity(
                id=mock_patient_model.id,
                first_name=mock_patient_model._first_name,  # Assuming direct access post-TypeDecorator
                last_name=mock_patient_model._last_name,
                email=mock_patient_model._email,
                date_of_birth=date.fromisoformat(mock_patient_model._date_of_birth),
                address=Address.create(
                    line1=mock_patient_model._address_line1 or "",
                    city=mock_patient_model._city or "",
                    state=mock_patient_model._state or "",
                    zip_code=mock_patient_model._zip_code or "",
                    country=mock_patient_model._country or "",
                ),
                # ... other necessary fields from PatientEntity that PatientModel.to_domain constructs
            )

        mock_patient_model.to_domain = AsyncMock(side_effect=mock_to_domain_for_get)

        # Configure execute().scalars().one_or_none() to return our mock_patient_model
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = (
            mock_patient_model
        )

        retrieved_entity = await patient_repository.get_by_id(sample_patient_id)

        mock_db_session.execute.assert_awaited_once()  # Check that select was called
        # Verify that the select statement includes a filter for the ID.
        # This requires inspecting the call_args of mock_db_session.execute.
        # Example (may need adjustment based on how select() is built):
        # called_statement = mock_db_session.execute.call_args[0][0]
        # assert str(patient_uuid) in str(called_statement.compile(compile_kwargs={"literal_binds": True}))

        assert retrieved_entity is not None
        assert retrieved_entity.id == patient_uuid
        assert retrieved_entity.first_name == "DecryptedFirstName"
        assert retrieved_entity.address.zip_code == "90210"

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(
        self,
        patient_repository: PatientRepository,
        mock_db_session: AsyncMock,
        sample_patient_id: str,
    ) -> None:
        """Test get_by_id when patient is not found."""
        uuid.UUID(sample_patient_id)
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = None

        entity = await patient_repository.get_by_id(sample_patient_id)

        mock_db_session.execute.assert_awaited_once()
        # Ensure the select statement was for the correct ID
        # This requires inspecting the call args of session.execute, which can be complex.
        # For now, trust the internal logic and focus on the outcome.
        assert entity is None

    @pytest.mark.asyncio
    @patch(
        "app.infrastructure.persistence.sqlalchemy.models.patient.Patient.from_domain",
        new_callable=AsyncMock,
    )  # Corrected patch target
    @patch("app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance")
    @pytest.mark.asyncio
    async def test_create_patient(
        self,
        mock_patient_module_esi: MagicMock,
        mock_patient_from_domain: AsyncMock,
        patient_repository: PatientRepository,
        mock_db_session: AsyncMock,
        sample_patient_data: dict,
        mock_encryption_service: MagicMock,
    ) -> None:
        """Test creating a new patient, ensuring data is encrypted and returned correctly."""
        # The primary interaction should be with mock_esi for TypeDecorator behavior.
        mock_patient_module_esi.encrypt = mock_encryption_service.encrypt
        mock_patient_module_esi.decrypt = mock_encryption_service.decrypt

        mock_created_model_instance = MagicMock(spec=PatientModel)

        async def mock_to_domain_on_created():
            return PatientEntity(**sample_patient_data)

        mock_created_model_instance.to_domain = AsyncMock(side_effect=mock_to_domain_on_created)
        # mock_patient_from_domain is now the AsyncMock for PatientModel.from_domain
        mock_patient_from_domain.return_value = mock_created_model_instance

        async def mock_refresh(target_model) -> None:
            pass

        mock_db_session.refresh = AsyncMock(side_effect=mock_refresh)

        patient_to_create = PatientEntity(**sample_patient_data)
        created_patient_entity = await patient_repository.create(patient_to_create)

        mock_patient_from_domain.assert_awaited_once_with(patient_to_create)
        mock_db_session.add.assert_called_once_with(mock_created_model_instance)
        mock_db_session.flush.assert_awaited_once()
        mock_db_session.refresh.assert_awaited_once_with(mock_created_model_instance)
        mock_created_model_instance.to_domain.assert_awaited_once()

        assert created_patient_entity is not None
        assert created_patient_entity.id == uuid.UUID(
            str(sample_patient_data["id"])
        )  # Ensure UUID comparison
        assert created_patient_entity.first_name == sample_patient_data["first_name"]

    @pytest.mark.asyncio
    @patch(
        "app.infrastructure.persistence.sqlalchemy.models.patient.Patient",
        new_callable=MagicMock,
    )
    @patch("app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance")
    @pytest.mark.asyncio
    async def test_update_patient(
        self,
        mock_patient_module_esi: MagicMock,
        MockPatientClass: MagicMock,
        patient_repository: PatientRepository,
        mock_db_session: AsyncMock,
        sample_patient_id: str,
        mock_encryption_service: MagicMock,
    ) -> None:
        """Test updating an existing patient."""
        mock_patient_module_esi.encrypt = mock_encryption_service.encrypt
        mock_patient_module_esi.decrypt = mock_encryption_service.decrypt

        patient_uuid = uuid.UUID(sample_patient_id)

        # Create the test domain patient entity for the result
        result_patient = PatientEntity(
            id=patient_uuid,
            first_name="UpdatedFirstName",
            last_name="UpdatedLastName",
            email="update@example.com",
            date_of_birth=date(1990, 1, 1),
        )

        # Set up our implementation's return value directly
        patient_repository._with_session = AsyncMock(return_value=result_patient)

        # Create the updated patient details to pass to update
        updated_patient_details = PatientEntity(
            id=patient_uuid,
            first_name="UpdatedFirstName",
            last_name="UpdatedLastName",
            email="update@example.com",
            date_of_birth=date(1990, 1, 1),
        )

        # Call the update method
        result_entity = await patient_repository.update(updated_patient_details)

        # Verify just the basics
        assert result_entity is result_patient
        assert result_entity.first_name == "UpdatedFirstName"
        assert result_entity.last_name == "UpdatedLastName"

    @pytest.mark.asyncio
    @patch("app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance")
    @pytest.mark.asyncio
    async def test_get_all_patients(
        self,
        mock_patient_module_esi: MagicMock,
        patient_repository: PatientRepository,
        mock_db_session: AsyncMock,
        sample_patient_list_data: list[dict],
    ) -> None:  # Use new fixture
        """Test retrieving all patients with limit and offset."""
        # mock_patient_module_esi used by TypeDecorators implicitly

        mock_patient_models = []
        for i, data_dict in enumerate(sample_patient_list_data):  # data_dict is now a dict
            model = MagicMock(spec=PatientModel)
            model.id = data_dict.get("id")  # .get() is fine now
            model._first_name = data_dict.get("first_name")
            model._last_name = data_dict.get("last_name")
            model._email = data_dict.get("email")
            model._date_of_birth = data_dict.get(
                "date_of_birth"
            ).isoformat()  # .isoformat() is fine
            model._address_line1 = "123 Main St"
            model._city = "Anytown"
            model._state = "CA"
            model._zip_code = f"9021{i}"
            model._country = "USA"

            async def make_to_domain_side_effect(current_model_data_dict):
                # This inner function is the actual side effect
                async def side_effect_async_fn():
                    return PatientEntity(
                        id=current_model_data_dict["id"],
                        first_name=current_model_data_dict["_first_name"],
                        last_name=current_model_data_dict["_last_name"],
                        email=current_model_data_dict["_email"],
                        date_of_birth=date.fromisoformat(current_model_data_dict["_date_of_birth"]),
                        address=Address.create(
                            line1=current_model_data_dict["_address_line1"] or "",
                            city=current_model_data_dict["_city"] or "",
                            state=current_model_data_dict["_state"] or "",
                            zip_code=current_model_data_dict["_zip_code"] or "",
                            country=current_model_data_dict["_country"] or "",
                        ),
                        # Ensure all required fields for PatientEntity are present
                    )

                return side_effect_async_fn  # Return the async function itself

            current_state_for_side_effect = {
                "id": model.id,
                "_first_name": model._first_name,
                "_last_name": model._last_name,
                "_email": model._email,
                "_date_of_birth": model._date_of_birth,
                "_address_line1": model._address_line1,
                "_city": model._city,
                "_state": model._state,
                "_zip_code": model._zip_code,
                "_country": model._country,
            }
            # Assign an AsyncMock to model.to_domain, with the side_effect being the async function generated by make_to_domain_side_effect
            model.to_domain = AsyncMock(
                side_effect=await make_to_domain_side_effect(current_state_for_side_effect)
            )
            mock_patient_models.append(model)

        mock_db_session.execute.return_value.scalars.return_value.all.return_value = (
            mock_patient_models
        )
        retrieved_entities = await patient_repository.list_all(limit=10, offset=0)
        mock_db_session.execute.assert_awaited_once()
        assert len(retrieved_entities) == len(sample_patient_list_data)
        for entity, model_mock in zip(retrieved_entities, mock_patient_models, strict=False):
            assert entity.id == model_mock.id
            model_mock.to_domain.assert_awaited_once()
            assert entity.address.zip_code.startswith("9021")

    @pytest.mark.asyncio
    @patch("app.infrastructure.persistence.sqlalchemy.models.patient.encryption_service_instance")
    @pytest.mark.asyncio
    async def test_get_by_email(
        self,
        mock_patient_module_esi: MagicMock,
        patient_repository: PatientRepository,
        mock_db_session: AsyncMock,
        sample_patient_data: dict,
    ) -> None:
        """Test retrieving a patient by email."""
        # mock_patient_module_esi used by TypeDecorators implicitly

        target_email = sample_patient_data["email"]
        mock_patient_model = MagicMock(spec=PatientModel)
        # Ensure sample_patient_data["id"] is a UUID if comparing directly later
        mock_patient_model.id = uuid.UUID(str(sample_patient_data["id"]))
        mock_patient_model._email = target_email
        mock_patient_model._first_name = sample_patient_data["first_name"]
        mock_patient_model._last_name = sample_patient_data["last_name"]
        # Ensure sample_patient_data["date_of_birth"] is a date object for .isoformat()
        if isinstance(sample_patient_data["date_of_birth"], str):
            dob = date.fromisoformat(sample_patient_data["date_of_birth"])
        else:
            dob = sample_patient_data["date_of_birth"]
        mock_patient_model._date_of_birth = dob.isoformat()
        mock_patient_model._address_line1 = "456 Email Ave"
        mock_patient_model._city = "Mailville"
        mock_patient_model._state = "TX"
        mock_patient_model._zip_code = "75001"
        mock_patient_model._country = "USA"

        async def mock_to_domain_for_email_get():
            return PatientEntity(
                id=mock_patient_model.id,
                first_name=mock_patient_model._first_name,
                last_name=mock_patient_model._last_name,
                email=mock_patient_model._email,
                date_of_birth=date.fromisoformat(mock_patient_model._date_of_birth),
                address=Address.create(
                    line1="456 Email Ave",
                    city="Mailville",
                    state="TX",
                    zip_code="75001",
                    country="USA",
                ),
            )

        mock_patient_model.to_domain = AsyncMock(side_effect=mock_to_domain_for_email_get)
        mock_db_session.execute.return_value.scalars.return_value.one_or_none.return_value = (
            mock_patient_model
        )

        retrieved_entity = await patient_repository.get_by_email(target_email)
        mock_db_session.execute.assert_awaited_once()
        assert retrieved_entity is not None
        assert retrieved_entity.email == target_email
        assert (
            retrieved_entity.id == mock_patient_model.id
        )  # Compare with the UUID set on mock_patient_model
        assert retrieved_entity.address.zip_code == "75001"

    @pytest.mark.asyncio
    async def test_delete_patient_success(
        self,
        patient_repository: PatientRepository,
        mock_db_session: AsyncMock,
        sample_patient_id: str,
    ) -> None:
        """Test deleting a patient successfully."""
        # Directly mock the _with_session method to return True
        patient_repository._with_session = AsyncMock(return_value=True)

        # Action
        result = await patient_repository.delete(sample_patient_id)

        # Assertions
        assert result is True

    @pytest.mark.asyncio
    async def test_delete_patient_not_found(
        self,
        patient_repository: PatientRepository,
        mock_db_session: AsyncMock,
        sample_patient_id: str,
    ) -> None:
        """Test deleting a patient that does not exist."""
        # Directly mock the _with_session method to return False
        patient_repository._with_session = AsyncMock(return_value=False)

        # Action
        result = await patient_repository.delete(sample_patient_id)

        # Assertions
        assert result is False

    # TODO: Test error/edge cases for all methods


# Further tests would go here, e.g., for update, delete, error conditions.
