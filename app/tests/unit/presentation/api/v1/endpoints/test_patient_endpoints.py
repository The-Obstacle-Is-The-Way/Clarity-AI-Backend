import pytest
from unittest.mock import AsyncMock, MagicMock
from faker import Faker
from fastapi import status, FastAPI, HTTPException
from httpx import AsyncClient, Response, ASGITransport
import uuid
from datetime import date, datetime, timezone

# Add imports for managing lifespan explicitly
import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Tuple 

from app.application.services.patient_service import PatientService
# from app.main import app # REMOVED
from app.presentation.api.v1.routes.patient import get_patient_service

# Add imports for create_application and Settings
from app.app_factory import create_application
from app.core.config.settings import Settings as AppSettings # Use alias
from app.presentation.api.schemas.patient import PatientCreateRequest, PatientRead, PatientCreateResponse # Import schemas
from app.presentation.api.dependencies.auth import CurrentUserDep, get_current_user # MODIFIED: Removed DomainUser import from here
# CORRECTED DomainUser and related imports to align with auth.py
from app.core.domain.entities.user import User as DomainUser, UserStatus, UserRole 
# Import the dependency to override for read tests
from app.presentation.api.dependencies.patient import get_patient_id # CORRECTED NAME
from app.core.domain.entities.patient import Patient # Import Patient entity for mocking

# Helper context manager for lifespan
@asynccontextmanager
async def lifespan_wrapper(app: FastAPI) -> AsyncGenerator[None, None]:
    """Runs the app's lifespan startup and shutdown."""
    # Use the actual lifespan context manager if defined, otherwise fallback
    if app.router.lifespan_context:
        async with app.router.lifespan_context(app) as maybe_state:
            # If the lifespan yields state, it needs handling (FastAPI >= 0.107)
            # For older versions or lifespans not yielding state, this is simpler.
            # Assuming the current lifespan doesn't yield state for now.
            yield
    else: # Fallback for apps without lifespan context (older FastAPI?)
        await app.router.startup()
        try:
            yield
        finally:
            await app.router.shutdown()

# Fixture for App instance and AsyncClient
@pytest.fixture(scope="function") 
async def client(test_settings: AppSettings) -> Tuple[FastAPI, AsyncClient]:
    """Provides a FastAPI app instance and an AsyncClient instance scoped per test function."""
    app_instance = create_application(settings_override=test_settings)
    async with lifespan_wrapper(app_instance): # MODIFIED: Wrap client in lifespan
        async with AsyncClient(transport=ASGITransport(app=app_instance), base_url="http://test") as async_client: # Use transport explicitly
            yield app_instance, async_client
    app_instance.dependency_overrides.clear()

# Fixture to mock PatientService
@pytest.fixture(scope="function") 
def mock_service() -> AsyncMock:
    """Provides a mock PatientService scoped per test function."""
    return AsyncMock(spec=PatientService)

# Fixture for a mock user to satisfy auth dependency
@pytest.fixture
def mock_current_user() -> DomainUser:
    """Provides a mock active user for dependency overrides."""
    # DomainUser is now app.core.domain.entities.user.User (dataclass)
    user_id = uuid.uuid4()
    return DomainUser(
        id=user_id,
        email="testuser@example.com",
        username="testuser",
        full_name="Test User",
        password_hash="hashed_password_for_testing", # Required by dataclass
        roles={UserRole.ADMIN}, # Dataclass expects set[UserRole]
        status=UserStatus.ACTIVE # Dataclass expects UserStatus
    )

# Update based on PatientRead schema
TEST_PATIENT_ID = str(uuid.uuid4())
EXPECTED_PATIENT_READ = {
    "id": TEST_PATIENT_ID,
    "first_name": "Test",
    "last_name": "Patient",
    "date_of_birth": "1990-01-01",
    "email": "test.patient@example.com",
    "phone_number": "555-1234",
    "name": "Test Patient" # Computed field
}

@pytest.mark.asyncio
async def test_read_patient_success(client: tuple[FastAPI, AsyncClient], mock_service: AsyncMock, mock_current_user: DomainUser) -> None:
    """Test successful retrieval of a patient."""
    app_instance, async_client = client
    # Arrange
    test_patient_id = EXPECTED_PATIENT_READ["id"]
    
    # Mock the patient domain entity that the dependency should return
    mock_patient_entity = Patient(
        id=uuid.UUID(test_patient_id),
        first_name=EXPECTED_PATIENT_READ["first_name"],
        last_name=EXPECTED_PATIENT_READ["last_name"],
        date_of_birth=date.fromisoformat(EXPECTED_PATIENT_READ["date_of_birth"]),
        email=EXPECTED_PATIENT_READ["email"],
        phone_number=EXPECTED_PATIENT_READ["phone_number"],
        # Add other required fields for Patient entity if any, with dummy data
        created_by_id=mock_current_user.id # Assuming this might be needed
    )
    
    # Override the dependency that provides the patient entity
    app_instance.dependency_overrides[get_patient_id] = lambda: mock_patient_entity # CORRECTED NAME
    # We don't need to mock the service anymore for this read test, as the entity is provided directly
    # app_instance.dependency_overrides[get_patient_service] = lambda: mock_service 
    app_instance.dependency_overrides[get_current_user] = lambda: mock_current_user # Override auth

    # Act
    response: Response = await async_client.get(f"/api/v1/patients/{test_patient_id}")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    # The response should match the PatientRead schema derived from the mock_patient_entity
    # Reconstruct the expected JSON based on PatientRead schema
    expected_response_json = PatientRead.model_validate(mock_patient_entity).model_dump(mode="json")
    assert response.json() == expected_response_json
    # mock_service.get_patient_by_id.assert_awaited_once_with(test_patient_id)

    # Clean up overrides
    # del app_instance.dependency_overrides[get_patient_service]
    del app_instance.dependency_overrides[get_current_user]
    del app_instance.dependency_overrides[get_patient_id] # CORRECTED NAME

@pytest.mark.asyncio
async def test_read_patient_not_found(client: tuple[FastAPI, AsyncClient], mock_service: AsyncMock, mock_current_user: DomainUser) -> None:
    """Test GET /patients/{patient_id} when patient is not found."""
    app_instance, async_client = client
    # Arrange
    patient_id = str(uuid.uuid4()) # Use a valid UUID format
    
    # Mock the dependency to raise NotFound
    async def mock_dependency_not_found():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patient with id {patient_id} not found")
        
    app_instance.dependency_overrides[get_patient_id] = mock_dependency_not_found # CORRECTED NAME
    # app_instance.dependency_overrides[get_patient_service] = lambda: mock_service # Not needed
    app_instance.dependency_overrides[get_current_user] = lambda: mock_current_user # Override auth

    # Act
    response: Response = await async_client.get(f"/api/v1/patients/{patient_id}")

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"Patient with id {patient_id} not found"}
    # mock_service.get_patient_by_id.assert_awaited_once_with(patient_id) # Service not called

    # Clean up overrides
    # del app_instance.dependency_overrides[get_patient_service]
    del app_instance.dependency_overrides[get_current_user]
    del app_instance.dependency_overrides[get_patient_id] # CORRECTED NAME

@pytest.mark.asyncio
async def test_create_patient_success(client: tuple[FastAPI, AsyncClient], faker: Faker, mock_current_user: DomainUser) -> None:
    """Test successful creation of a patient."""
    app_instance, async_client = client

    # Define stubs and overrides
    async def stub_create_patient(payload: PatientCreateRequest, created_by_id: uuid.UUID) -> PatientCreateResponse:
        # Simulate service creating the patient
        assert created_by_id == mock_current_user.id # Verify correct user ID passed
        return PatientCreateResponse(
            id=uuid.uuid4(), # Generate a new ID for the response
            first_name=payload.first_name,
            last_name=payload.last_name,
            date_of_birth=payload.date_of_birth,
            created_at=datetime.now(timezone.utc), # Use timezone-aware datetime
            updated_at=datetime.now(timezone.utc),
            created_by=created_by_id
        )

    class StubPatientService:
        create_patient = stub_create_patient

    # Override the service dependency with the stub instance
    app_instance.dependency_overrides[get_patient_service] = lambda: StubPatientService()
    
    # MODIFIED: Revert to simple lambda override
    app_instance.dependency_overrides[get_current_user] = lambda: mock_current_user

    # Setup a domain user that would be returned by the (now real but simplified) get_current_user
    patient_payload = { 
        "first_name": faker.first_name(),
        "last_name": faker.last_name(),
        "date_of_birth": faker.date_of_birth(minimum_age=18, maximum_age=90).isoformat(),
        "email": faker.email(),
        "phone_number": faker.phone_number()
    }
    
    # Use a simple stub instead of AsyncMock for the service
    created_patient_id = str(uuid.uuid4())
    service_call_tracker = {"called": False, "args": None, "kwargs": None}
    
    async def stub_create_patient(patient_data, created_by_id):
        # Correct indentation for function body
        service_call_tracker["called"] = True
        service_call_tracker["args"] = (patient_data,)
        service_call_tracker["kwargs"] = {"created_by_id": created_by_id}
        # Return data matching PatientCreateResponse structure
        return PatientCreateResponse(
             id=created_patient_id,
             first_name=patient_data.first_name,
             last_name=patient_data.last_name,
             date_of_birth=patient_data.date_of_birth,
             email=patient_data.email,
             phone_number=patient_data.phone_number
        )

    class StubPatientService:
        create_patient = stub_create_patient

    # Override the service dependency with the stub instance
    app_instance.dependency_overrides[get_patient_service] = lambda: StubPatientService()
    # MODIFIED: Restore the override for get_current_user
    app_instance.dependency_overrides[get_current_user] = lambda: mock_current_user

    # Act
    # WORKAROUND: Add dummy query params '?args=ignore&kwargs=ignore'.
    # This is required to bypass a FastAPI issue where dependency_overrides combined
    # with the original dependency's use of HTTPBearer causes FastAPI to incorrectly 
    # demand 'args' and 'kwargs' query parameters (resulting in a 422 error).
    # See FastAPI GitHub issue #3331. 
    # NOTE: This workaround currently leads to a subsequent TypeError during dependency 
    # resolution (User.__init__() got an unexpected keyword argument 'args'), as FastAPI 
    # attempts to pass these query params into the User dataclass initialization.
    # This test is expected to FAIL with that TypeError until the underlying issue 
    # or a better workaround is found.
    response: Response = await async_client.post("/api/v1/patients/?args=ignore&kwargs=ignore", json=patient_payload)

    # Assert Status Code
    assert response.status_code == status.HTTP_201_CREATED, f"Expected 201, got {response.status_code}. Response: {response.text}"
    
    # Assert Response Body (matching PatientCreateResponse)
    response_data = response.json()
    assert response_data["id"] == created_patient_id
    assert response_data["first_name"] == patient_payload["first_name"]
    assert response_data["last_name"] == patient_payload["last_name"]
    assert response_data["date_of_birth"] == patient_payload["date_of_birth"]
    assert response_data["email"] == patient_payload["email"]
    assert response_data["phone_number"] == patient_payload["phone_number"]

    # Assert Service Call (using tracker)
    assert service_call_tracker["called"] is True
    call_args, call_kwargs = service_call_tracker["args"], service_call_tracker["kwargs"]
    assert isinstance(call_args[0], PatientCreateRequest)
    assert call_args[0].first_name == patient_payload["first_name"]
    assert call_args[0].last_name == patient_payload["last_name"]
    assert call_args[0].date_of_birth.isoformat() == patient_payload["date_of_birth"]
    assert call_args[0].email == patient_payload["email"]
    assert call_args[0].phone_number == patient_payload["phone_number"]
    assert call_kwargs.get("created_by_id") == mock_current_user.id

    # Clean up overrides
    del app_instance.dependency_overrides[get_patient_service]
    # MODIFIED: Restore deletion of get_current_user override
    if get_current_user in app_instance.dependency_overrides:
        del app_instance.dependency_overrides[get_current_user]

@pytest.mark.asyncio
async def test_create_patient_validation_error(client: tuple[FastAPI, AsyncClient], faker: Faker, mock_current_user: DomainUser) -> None:
    """Test validation error during patient creation (e.g., missing fields)."""
    app_instance, async_client = client
    # MODIFIED: Restore the override here as well
    app_instance.dependency_overrides[get_current_user] = lambda: mock_current_user

    # Invalid payload missing required fields (first_name, last_name, date_of_birth)
    invalid_payload = {
        "email": faker.email()
    }

    # Act: Make the request using the client
    # WORKAROUND: Add dummy query params '?args=ignore&kwargs=ignore'.
    # See explanation in test_create_patient_success.
    # This test is also expected to FAIL with TypeError: User.__init__() got an unexpected keyword argument 'args'.
    response: Response = await async_client.post("/api/v1/patients/?args=ignore&kwargs=ignore", json=invalid_payload)

    # Assertions
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    response_data = response.json()
    assert "detail" in response_data
    
    # Check for specific missing field errors
    # This part depends on your exact Pydantic model and FastAPI version error formatting.
    # Example check assuming detail is a list of error objects:
    actual_missing_fields_locs = sorted([tuple(err["loc"]) for err in response_data["detail"] if err["type"] == "missing"])
    expected_missing_fields_locs = sorted([("body", "first_name"), ("body", "last_name"), ("body", "date_of_birth")])
    
    assert actual_missing_fields_locs == expected_missing_fields_locs, \
        f"Expected missing fields {{expected_missing_fields_locs}}, got {{actual_missing_fields_locs}}"

    # MODIFIED: Restore deletion of get_current_user override
    if get_current_user in app_instance.dependency_overrides:
        del app_instance.dependency_overrides[get_current_user]

# Placeholder for future tests
@pytest.mark.asyncio
async def test_read_patient_unauthorized() -> None:
    pytest.skip("Placeholder test - needs implementation")

@pytest.mark.asyncio
async def test_read_patient_invalid_id() -> None:
    pytest.skip("Placeholder test - needs implementation")

# Additional tests for create, update, delete endpoints should be added here
# when those endpoints are implemented.
# Remember to test edge cases, validation errors, and authorization.
