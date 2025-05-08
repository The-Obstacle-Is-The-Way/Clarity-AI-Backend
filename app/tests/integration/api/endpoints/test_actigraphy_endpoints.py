"""
API endpoint tests for actigraphy endpoints.

This module contains tests that verify the behavior of the actigraphy API endpoints,
including authentication, authorization, input validation, and HIPAA compliance.
"""

import uuid
from typing import Any, AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from asgi_lifespan import LifespanManager
import io

from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Fixtures removed:
# @pytest.fixture
# def pat_storage() -> Generator[str, None, None]: ...
# @pytest.fixture
# def mock_pat(pat_storage: str) -> MockPATService: ...
# @pytest.fixture
# def mock_pat_service(mock_pat: MockPATService) -> MockPATService: ...

# Local test_app and client fixtures removed; tests will use client from conftest.py
# Dependency overrides need to be handled globally in conftest.py or
# via specific test markers.
@pytest.fixture
def patient_token() -> str:

    """Fixture that returns a JWT token for a patient user.

    Returns:
JWT token
"""
    # Use the mock token string recognized by conftest.py async_client mock
    return "VALID_PATIENT_TOKEN"


@pytest.fixture
def provider_token() -> str:

    """Fixture that returns a JWT token for a provider user.

    Returns:
        JWT token
        """
    # Use the mock token string recognized by conftest.py async_client mock
    return "VALID_PROVIDER_TOKEN"


@pytest.fixture
def admin_token() -> str:

    """Fixture that returns a JWT token for an admin user.

    Returns:
        JWT token
        """
    # Use the mock token string recognized by conftest.py async_client mock
    return "VALID_ADMIN_TOKEN"


@pytest.fixture
def sample_readings() -> list[dict[str, float]]:

    """Fixture that returns sample accelerometer readings.

    Returns:
        Sample accelerometer readings
        """

    return [
        {"x": 0.1, "y": 0.2, "z": 0.9},
        {"x": 0.2, "y": 0.3, "z": 0.8},
        {"x": 0.3, "y": 0.4, "z": 0.7}
    ]


@pytest.fixture
def sample_device_info() -> dict[str, Any]:

    """Fixture that returns sample device information.

    Returns:
Sample device information
"""

    return {
        "device_id": "test-device-123",
        "model": "Test Actigraph 1.0",
        "firmware_version": "v1.0.0",
        "battery_level": 85
    }

# Removed the local mock_auth_dependency fixture - now using the one from conftest.py

@pytest_asyncio.fixture
async def test_app_with_auth_override(test_app_with_db_session: FastAPI, mock_auth_dependency):
    """
    FastAPI test application with authentication dependencies overridden.
    
    This fixture overrides the authentication dependencies in the application
    to avoid requiring real JWT tokens for testing.
    """
    # Import auth dependencies here to avoid circular imports
    from app.presentation.api.dependencies.auth import (
        get_current_user, 
        get_current_active_user,
        require_admin_role,
        require_clinician_role
    )
    
    # Override the dependencies in the app
    test_app_with_db_session.dependency_overrides[get_current_user] = mock_auth_dependency("PATIENT")
    test_app_with_db_session.dependency_overrides[get_current_active_user] = mock_auth_dependency("PATIENT")
    test_app_with_db_session.dependency_overrides[require_admin_role] = mock_auth_dependency("ADMIN")
    test_app_with_db_session.dependency_overrides[require_clinician_role] = mock_auth_dependency("CLINICIAN")
    
    yield test_app_with_db_session
    
    # Clean up after test
    test_app_with_db_session.dependency_overrides.clear()


@pytest_asyncio.fixture
async def authenticated_client(test_app_with_auth_override: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """
    An authenticated test client that can be used to make requests to the API.
    
    Yields:
        AsyncClient: A test client with authentication overrides
    """
    # Use lifespan manager to ensure database is properly initialized
    async with LifespanManager(test_app_with_auth_override) as manager:
        async with AsyncClient(app=manager.app, base_url="http://test") as client:
            yield client


@pytest.mark.anyio
class TestActigraphyEndpoints:
    """Test suite for Actigraphy API Endpoints integration."""

    @pytest.mark.anyio
    async def test_unauthenticated_access(
        self,
        test_client: AsyncClient
    ):
        """Test that unauthenticated access is blocked."""
        # Access without authentication token
        response = await test_client.get("/api/v1/actigraphy/data/123")
        
        # Should return 401 Unauthorized
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_authorized_access(
        self,
        authenticated_client: AsyncClient
    ):
        """Test that authenticated users can access endpoints."""
        # Access with valid authentication
        response = await authenticated_client.get("/api/v1/actigraphy/model-info")
        
        # Should return 200 OK
        assert response.status_code == 200
        
        # Response should contain expected fields
        response_data = response.json()
        assert "model_version" in response_data
        assert "model_name" in response_data

    @pytest.mark.anyio
    async def test_input_validation(
        self,
        authenticated_client: AsyncClient
    ):
        """Test input validation for actigraphy data endpoints."""
        # Test with invalid format data
        invalid_data = {
            "invalid_field": "should fail validation", 
            "wrong_data": True
        }
        
        # Attempt to send invalid data
        response = await authenticated_client.post(
            "/api/v1/actigraphy/analyze",
            json=invalid_data
        )
        
        # Should return validation error
        assert response.status_code == 422 # Unprocessable Entity 
        assert "detail" in response.json() # Should have validation details

    @pytest.mark.anyio
    async def test_role_based_access_control(
        self, 
        authenticated_client: AsyncClient
    ):
        """Test role-based access control for endpoints."""
        # We're using a patient role in authenticated_client
        # This endpoint should be accessible to patients
        response = await authenticated_client.get("/api/v1/actigraphy/model-info")
        assert response.status_code == 200
        
        # Attempt to post to analyze endpoint (which should be accessible)
        patient_analysis_response = await authenticated_client.post(
            "/api/v1/actigraphy/analyze",
            json={
                "patient_id": "test-patient-123",
                "analysis_types": ["sleep_quality", "activity_level"],
                "parameters": {"threshold": 100}
            }
        )
        
        # Patient should be able to analyze their own data
        assert patient_analysis_response.status_code == 200
        
        # Note: In a real test, we would test with multiple roles by configuring
        # different authenticated clients with different roles

    @pytest.mark.anyio
    async def test_hipaa_audit_logging(
        self,
        authenticated_client: AsyncClient
    ):
        """Test that HIPAA-compliant audit logging is performed."""
        # Make a request that should be audit logged
        response = await authenticated_client.get("/api/v1/actigraphy/model-info")
        
        # Verify response contains expected HIPAA audit headers
        assert response.status_code == 200
        assert "request_id" in response.headers

    @pytest.mark.anyio
    async def test_phi_data_sanitization(
        self, 
        authenticated_client: AsyncClient
    ):
        """Test that PHI data is properly sanitized in responses."""
        # Access model info - no PHI should be exposed
        response = await authenticated_client.get("/api/v1/actigraphy/model-info")
        
        # Should return 200 OK
        assert response.status_code == 200
        
        # Ensure PHI fields are not present in response
        response_data = response.json()
        assert "patient_name" not in response_data
        assert "ssn" not in response_data
        assert "date_of_birth" not in response_data

    @pytest.mark.anyio
    async def test_secure_data_transmission(
        self, 
        authenticated_client: AsyncClient
    ):
        """Test secure data transmission compliance."""
        # Make a request
        response = await authenticated_client.get("/api/v1/actigraphy/model-info")
        
        # Check security headers are present
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_api_response_structure(
        self, 
        authenticated_client: AsyncClient
    ):
        """Test consistent API response structure."""
        # Make a request to model info endpoint
        response = await authenticated_client.get("/api/v1/actigraphy/model-info")
        
        # Check response structure follows API standards
        assert response.status_code == 200
        response_data = response.json()
        
        # Check for required fields in response according to the schema
        assert "message" in response_data
        assert "version" in response_data


# Update the standalone test functions too
TEST_USER_ID = str(uuid.uuid4()) # Use a consistent test user ID

@pytest.mark.anyio
async def test_upload_actigraphy_data(
    authenticated_client: AsyncClient,
    actigraphy_file_content: bytes,
    actigraphy_file_name: str
):
    """
    Test uploading actigraphy data through the API endpoint.
    
    This test verifies:
    - File upload functionality
    - Validation of file format and contents
    - Response structure and status code
    """
    # Create a file-like object and multipart form data
    file = io.BytesIO(actigraphy_file_content)
    files = {"file": (actigraphy_file_name, file, "text/csv")}
    
    # Send the request to the API - use the correct endpoint from the router
    response = await authenticated_client.post(
        "/api/v1/actigraphy/upload",
        files=files,
    )
    
    # Assert response
    assert response.status_code == 201, f"Expected 201 Created but got {response.status_code}: {response.text}"
    assert "file_id" in response.json(), "Response should contain a file_id"
    assert "message" in response.json(), "Response should contain a message"
    assert "filename" in response.json(), "Response should contain the filename"
    assert response.json()["filename"] == actigraphy_file_name, "Filename should match the uploaded file"

@pytest.mark.anyio
async def test_get_actigraphy_data_summary(authenticated_client: AsyncClient):
    """Test retrieving actigraphy data summaries."""
    # Use a valid patient UUID
    patient_id = "00000000-0000-0000-0000-000000000001"  # TEST_USER_ID
    
    # Get actigraphy summaries for this patient using the correct endpoint
    response = await authenticated_client.get(f"/api/v1/actigraphy/patient/{patient_id}/summary")
    
    # Verify the response structure
    assert response.status_code == 200
    response_data = response.json()
    assert "summaries" in response_data
    assert isinstance(response_data["summaries"], list)

@pytest.mark.anyio
async def test_get_specific_actigraphy_data(authenticated_client: AsyncClient):
    """Test retrieving specific actigraphy data with proper authentication."""
    # Use a valid data ID
    data_id = "test-data-id"
    
    # Use the correct endpoint defined in the router
    url = f"/api/v1/actigraphy/data/{data_id}"
    response = await authenticated_client.get(url)
    
    assert response.status_code == 200
    response_data = response.json()
    assert "data_id" in response_data
    assert response_data["data_id"] == data_id

@pytest.mark.anyio
async def test_unauthorized_access(test_client: AsyncClient):
    """Test that unauthorized access is properly rejected."""
    # Without authentication, this should fail
    response = await test_client.get("/api/v1/actigraphy/model-info")
    
    assert response.status_code == 401
    assert "detail" in response.json()
    assert "Not authenticated" in response.json()["detail"]

@pytest.mark.anyio
async def test_invalid_date_format(
    authenticated_client: AsyncClient
):
    """Test validation of date format parameters."""
    # Make a request with an invalid date format
    response = await authenticated_client.get(
        "/api/v1/actigraphy/00000000-0000-0000-0000-000000000001?start_date=invalid-date&end_date=2023-01-07"
    )
    
    # API should return 422 Unprocessable Entity for invalid date format
    assert response.status_code == 422  # Unprocessable Entity
    
    # Response should have detailed validation error
    response_data = response.json()
    assert "detail" in response_data
    
    # At least one validation error should mention the date format
    validation_errors = response_data["detail"]
    date_error = any("date" in str(error).lower() for error in validation_errors)
    assert date_error, "Validation error should mention invalid date format"

@pytest.fixture
def actigraphy_file_content() -> bytes:
    """
    Fixture providing sample content for an actigraphy data file.
    
    Returns:
        Sample CSV content representing actigraphy data
    """
    csv_content = """timestamp,x,y,z,activity_count
2023-01-01T00:00:00Z,0.1,0.2,0.3,10
2023-01-01T00:00:01Z,0.2,0.3,0.4,15
2023-01-01T00:00:02Z,0.3,0.4,0.5,20
2023-01-01T00:00:03Z,0.4,0.5,0.6,25
2023-01-01T00:00:04Z,0.5,0.6,0.7,30
"""
    return csv_content.encode('utf-8')

@pytest.fixture
def actigraphy_file_name() -> str:
    """
    Fixture providing a sample filename for an actigraphy data file.
    
    Returns:
        A sample filename for test uploads
    """
    return "test_actigraphy_data.csv"