import pytest
from unittest.mock import AsyncMock
from faker import Faker
from fastapi import status, FastAPI
from httpx import AsyncClient, Response

from app.application.services.patient_service import PatientService
from app.main import app
from app.presentation.api.v1.routes.patient import get_patient_service

# Fixture for AsyncClient
@pytest.fixture(scope="function") 
async def client() -> AsyncClient:
    """Provides an AsyncClient instance scoped per test function."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

# Fixture to mock PatientService
@pytest.fixture(scope="function") 
def mock_service() -> AsyncMock:
    """Provides a mock PatientService scoped per test function."""
    return AsyncMock(spec=PatientService)

# Mock Patient Data matching the PatientRead schema
EXPECTED_PATIENT_DATA = {"id": "test_patient_123", "name": "Test Patient Name"}
EXPECTED_NOT_FOUND_DETAIL = {"detail": "Patient with id non-existent-patient not found"}

# Remove test_placeholder, implement actual test
@pytest.mark.asyncio
async def test_read_patient_success(client: AsyncClient, mock_service: AsyncMock) -> None:
    """Test successful retrieval of a patient."""
    # Arrange
    expected_patient_data = {"id": "test-patient-123", "name": "Test Patient Name"}
    test_patient_id = expected_patient_data["id"]
    # Configure the mock to return the expected data when called
    mock_service.get_patient_by_id.return_value = expected_patient_data
    # Override the dependency for this test
    app.dependency_overrides[get_patient_service] = lambda: mock_service

    # Act
    response: Response = await client.get(f"/api/v1/patients/{test_patient_id}")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == expected_patient_data
    mock_service.get_patient_by_id.assert_awaited_once_with(test_patient_id)

    # Clean up the dependency override after the test
    del app.dependency_overrides[get_patient_service]

@pytest.mark.asyncio
async def test_read_patient_not_found(client: AsyncClient, mock_service: AsyncMock) -> None:
    """Test GET /patients/{patient_id} when patient is not found."""
    # Arrange
    patient_id = "non-existent-patient"
    mock_service.get_patient_by_id.return_value = None # Service returns None
    app.dependency_overrides[get_patient_service] = lambda: mock_service

    # Act
    response: Response = await client.get(f"/api/v1/patients/{patient_id}")

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"Patient with id {patient_id} not found"}
    mock_service.get_patient_by_id.assert_awaited_once_with(patient_id)

    # Clean up
    del app.dependency_overrides[get_patient_service]

@pytest.mark.asyncio
async def test_create_patient_success(client: AsyncClient, mock_service: AsyncMock) -> None:
    """Test POST /patients/ successfully creating a patient."""
    # Arrange
    patient_payload = {"name": "New Test Patient"}
    expected_created_patient = {
        "id": "new-generated-id-456",
        "name": patient_payload["name"]
    }
    # Configure the mock to return the expected data when called
    mock_service.create_patient.return_value = expected_created_patient
    # Override the dependency for this test
    app.dependency_overrides[get_patient_service] = lambda: mock_service

    # Act
    response: Response = await client.post("/api/v1/patients/", json=patient_payload)

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() == expected_created_patient

    # Verify the service method was called correctly
    # Pydantic models passed to mocks might require special handling or checking attributes
    # For now, check it was called once. More specific checks can be added.
    mock_service.create_patient.assert_called_once()
    call_args, call_kwargs = mock_service.create_patient.call_args
    # Check the argument passed was a PatientCreateRequest instance (or compatible dict)
    # isinstance check might be better if service expects the Pydantic model directly
    assert call_args[0].name == patient_payload["name"] 
    # or assert call_args[0] == PatientCreateRequest(**patient_payload)

    # Clean up the dependency override after the test
    del app.dependency_overrides[get_patient_service]

@pytest.mark.asyncio
async def test_create_patient_validation_error(
    faker: Faker,
    initialized_app: tuple[FastAPI, AsyncClient, AsyncMock] # Depend only on this
) -> None:
    """Test validation error during patient creation (e.g., missing fields)."""
    app_instance, test_client, mock_session = initialized_app # Unpack app, client, session

    # Prepare invalid data (e.g., missing required fields)
    invalid_payload = {
        "first_name": faker.first_name(),
        # 'last_name', 'date_of_birth', 'contact_number' are missing
    }

    # Override is already handled by initialized_app fixture
    # logger.info(f"Override should be applied globally by initialized_app for {get_async_session}")

    # Act: Make the request using the client from initialized_app
    response: Response = await test_client.post("/api/v1/patients/", json=invalid_payload)

    # Assertions
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    response_json = response.json()
    assert "detail" in response_json
    # Verify specific validation errors are present in the response detail
    assert any(err["loc"] == ["body", "last_name"] for err in response_json["detail"])
    assert any(err["loc"] == ["body", "date_of_birth"] for err in response_json["detail"])
    assert any(err["loc"] == ["body", "contact_number"] for err in response_json["detail"])

# Placeholder for future tests
def test_read_patient_unauthorized() -> None:
    pass

def test_read_patient_invalid_id() -> None:
    pass

# Additional tests for create, update, delete endpoints should be added here
# when those endpoints are implemented.
# Remember to test edge cases, validation errors, and authorization.
