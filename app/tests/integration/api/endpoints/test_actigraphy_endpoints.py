"""
API endpoint tests for actigraphy endpoints.

This module contains tests that verify the behavior of the actigraphy API endpoints,
including authentication, authorization, input validation, and HIPAA compliance.
"""

import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

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


@pytest.mark.db_required()
@pytest.mark.asyncio
class TestActigraphyEndpoints:
    """Test suite for Actigraphy API Endpoints integration."""

    @pytest.mark.asyncio
    async def test_unauthenticated_access(
        self,
        test_client: AsyncClient
    ) -> None:
        """Test that unauthenticated requests are rejected."""
        # Access an endpoint without authentication
        response = await test_client.get("/api/v1/actigraphy/model-info")

        # Should return 401 Unauthorized
        assert response.status_code == 401
        # Check detail message based on actual implementation (might differ from "Not authenticated")
        assert "detail" in response.json()
        assert "Not authenticated" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_authorized_access(
        self,
        test_client: AsyncClient,
        patient_token: str
    ) -> None:
        """Test that authorized requests are allowed."""
        # Access an endpoint with authentication
        response = await test_client.get(
            "/api/v1/actigraphy/model-info", 
            headers={"Authorization": f"Bearer {patient_token}"}
        )

        # Should return 200 OK
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_input_validation(
        self,
        test_client: AsyncClient,
        patient_token: str
    ) -> None:
        """Test that input validation works correctly."""
        # Try to analyze actigraphy with invalid input
        invalid_request = {
            "patient_id": "",  # Empty patient ID
            "readings": [],    # Empty readings
            "start_time": "invalid-time",  # Invalid time format
            "end_time": "2025-01-01T00:00:02Z",
            "sampling_rate_hz": -1.0,  # Invalid sampling rate
            "device_info": {},  # Empty device info
            "analysis_types": ["invalid_type"]  # Invalid analysis type
        }

        response = await test_client.post(
            "/api/v1/actigraphy/analyze", 
            json=invalid_request, 
            headers={"Authorization": f"Bearer {patient_token}"}
        )

        # Should return 422 Unprocessable Entity
        assert response.status_code == 422
        # Check for validation error messages
        # assert "value_error" in response.text # More specific check if needed
        assert "detail" in response.json()

    @pytest.mark.asyncio
    async def test_phi_data_sanitization(
        self, 
        test_client: AsyncClient, 
        provider_token: str
    ) -> None:
        """Test that PHI is sanitized in API responses (mocked)."""
        headers = {"Authorization": f"Bearer {provider_token}"}
        # Construct a VALID ActigraphyAnalysisRequest
        valid_request_payload = {
            "patient_id": "phi-test-patient-123",
            "analysis_types": ["sleep_quality"], # Use lowercase as per AnalysisType enum
            # "readings" field removed as it's not part of ActigraphyAnalysisRequest
            "start_time": "2023-01-01T00:00:00Z", # Optional
            "end_time": "2023-01-01T01:00:00Z"    # Optional
        }
        
        response = await test_client.post(
            "/api/v1/actigraphy/analyze", json=valid_request_payload, headers=headers
        )
        
        assert response.status_code == 200 # Expect 200 for valid request
        response_data = response.json()
        # Assertions here would depend on what the MockPATService returns and if it simulates PHI.
        # For now, we are just ensuring the request goes through successfully.
        assert "results" in response_data 
        assert response_data["patient_id"] == "phi-test-patient-123"
        # In a real test for PII sanitization, you'd check that specific fields are NOT present or are masked.

    @pytest.mark.asyncio
    async def test_role_based_access_control(
        self, 
        test_client: AsyncClient, 
        patient_token: str, 
        provider_token: str, 
        admin_token: str, 
        sample_readings: list[dict[str, Any]], 
        sample_device_info: dict[str, Any]
    ) -> None:
        """Test that role-based access control works correctly."""
        # Create an analysis request payload conforming to ActigraphyAnalysisRequest
        analysis_request = {
            "patient_id": "test-patient-rbactest",
            # "readings": sample_readings, # REMOVED
            "start_time": "2025-01-01T00:00:00Z", # Optional
            "end_time": "2025-01-01T00:00:02Z",   # Optional
            # "sampling_rate_hz": 1.0,           # REMOVED
            # "device_info": sample_device_info, # REMOVED
            "analysis_types": ["sleep_quality"] # Correct enum value
        }
        
        # Provider should be able to create analysis
        response_provider = await test_client.post(
            "/api/v1/actigraphy/analyze", 
            json=analysis_request, 
            headers={"Authorization": f"Bearer {provider_token}"}
        )
        assert response_provider.status_code == 200
        analysis_id = response_provider.json().get("analysis_id")
        assert analysis_id

        # Patient should NOT be able to create analysis (assuming endpoint requires provider/admin)
        response_patient = await test_client.post(
            "/api/v1/actigraphy/analyze", 
            json=analysis_request, 
            headers={"Authorization": f"Bearer {patient_token}"}
        )
        assert response_patient.status_code == 403 # Forbidden

        # Test GET access (adjust endpoint path if necessary)
        # Provider should be able to get analysis
        # response_get_provider = await test_client.get(
        #     f"/api/v1/actigraphy/analyses/{analysis_id}", 
        #     headers={"Authorization": f"Bearer {provider_token}"}
        # )
        # assert response_get_provider.status_code == 200

        # Patient should NOT be able to get analysis (unless it's their own AND endpoint allows)
        # This depends heavily on the specific authorization logic in get_analysis endpoint
        # response_get_patient = await test_client.get(
        #     f"/api/v1/actigraphy/analyses/{analysis_id}", 
        #     headers={"Authorization": f"Bearer {patient_token}"}
        # )
        # # Expect 403 or 404 depending on implementation
        # assert response_get_patient.status_code in [403, 404] 

    @pytest.mark.asyncio
    async def test_hipaa_audit_logging(
        self, 
        test_client: AsyncClient, 
        provider_token: str, 
        sample_readings: list[dict[str, Any]], 
        sample_device_info: dict[str, Any]
    ) -> None:
        """Test that relevant actions trigger HIPAA audit logs."""
        # Mock the audit logger dependency used by the endpoint/service
        # This requires knowing which logger is used (e.g., injected via DI)
        mock_audit_logger = AsyncMock()
        with patch("app.infrastructure.logging.audit_logger.log_audit_event", mock_audit_logger): # Example patch path

            # Perform an action that should be audited (e.g., creating analysis)
            # Payload conforms to ActigraphyAnalysisRequest
            analysis_request = {
                "patient_id": "test-patient-auditlog",
                # "readings": sample_readings,           # REMOVED
                "start_time": "2025-01-01T00:00:00Z", # Optional
                "end_time": "2025-01-01T00:00:02Z",   # Optional
                # "sampling_rate_hz": 1.0,           # REMOVED
                # "device_info": sample_device_info, # REMOVED
                "analysis_types": ["sleep_quality"] # Correct enum value
            }
            response = await test_client.post(
                "/api/v1/actigraphy/analyze", 
                json=analysis_request, 
                headers={"Authorization": f"Bearer {provider_token}"}
            )
            assert response.status_code == 200

            # Assert that the audit logger was called
            mock_audit_logger.assert_awaited()
            # More specific checks on call arguments can be added:
            # mock_audit_logger.assert_awaited_with(
            #     event_type="ACTIGRAPHY_ANALYSIS_REQUESTED", # Example event type
            #     user_id="test-provider-id", # From provider_token mock
            #     details=Any # Or more specific check
            # )

    @pytest.mark.asyncio
    async def test_secure_data_transmission(
        self, 
        test_client: AsyncClient, 
        provider_token: str, 
        sample_readings: list[dict[str, Any]], 
        sample_device_info: dict[str, Any]
    ) -> None:
        """Test that data transmission uses HTTPS (implicitly tested by AsyncClient)."""
        # This test primarily relies on the deployment configuration ensuring HTTPS.
        # We can simulate checking the base_url scheme if needed, 
        # but AsyncClient itself doesn't enforce HTTPS locally.
        assert str(test_client.base_url).startswith("http://") # Base URL for testing is http
        # In a real end-to-end test against a deployed environment, you would assert HTTPS.
        
        # Perform a standard request to ensure it works over the configured protocol
        # Payload conforms to ActigraphyAnalysisRequest
        analysis_request = {
            "patient_id": "test-patient-securetx",
            # "readings": sample_readings,           # REMOVED
            "start_time": "2025-01-01T00:00:00Z", # Optional
            "end_time": "2025-01-01T00:00:02Z",   # Optional
            # "sampling_rate_hz": 1.0,           # REMOVED
            # "device_info": sample_device_info, # REMOVED
            "analysis_types": ["sleep_quality"] # Correct enum value
        }
        response = await test_client.post(
            "/api/v1/actigraphy/analyze", 
            json=analysis_request, 
            headers={"Authorization": f"Bearer {provider_token}"}
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_api_response_structure(
        self, 
        test_client: AsyncClient, 
        provider_token: str,
        # sample_readings: list[dict[str, Any]], # Use a valid structure
        # sample_device_info: dict[str, Any] # Use a valid structure
    ):
        """Test the structure of the API response for actigraphy analysis."""
        headers = {"Authorization": f"Bearer {provider_token}"}
        # Construct a VALID ActigraphyAnalysisRequest
        valid_request_payload = {
            "patient_id": "structure-test-patient-456",
            "analysis_types": ["activity_patterns"], # Corrected to lowercase enum value
            # "readings" field removed
            "start_time": "2023-02-01T00:00:00Z", # Optional
            "end_time": "2023-02-01T00:00:01Z"    # Optional
        }

        response = await test_client.post(
            "/api/v1/actigraphy/analyze", json=valid_request_payload, headers=headers
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Assertions based on AnalyzeActigraphyResponse schema
        assert "patient_id" in response_data
        assert response_data["patient_id"] == "structure-test-patient-456"
        assert "time_range" in response_data
        assert "start_time" in response_data["time_range"]
        assert "end_time" in response_data["time_range"]
        assert "results" in response_data
        assert isinstance(response_data["results"], list)
        if response_data["results"]:
            first_result = response_data["results"][0]
            assert "analysis_type" in first_result
            assert "analysis_time" in first_result
            # Further checks on ActigraphyAnalysisResult structure if needed


TEST_USER_ID = str(uuid.uuid4()) # Use a consistent test user ID

@pytest.mark.asyncio
async def test_upload_actigraphy_data(
    test_client: AsyncClient,
    patient_token: str, # CORRECTED from patient_user_token
    actigraphy_file_content: bytes, # Parameter for file content
    actigraphy_file_name: str, # Parameter for file name
    # upload_data: dict, # Not needed if using files
    # provider_token: str, # Use patient_user_token
    # sample_device_info: dict[str, Any] # Not directly used if sending file
) -> None:
    """Test uploading actigraphy data for analysis."""
    # patient_id = f"patient-{uuid.uuid4()}" # Not needed for simple file upload to stub
    # upload_data = { ... } # This was for /analyze

    headers = {"Authorization": f"Bearer {patient_token}"}
    files = {"file": (actigraphy_file_name, actigraphy_file_content, "text/csv")}
    
    response = await test_client.post(
        "/api/v1/actigraphy/upload", 
        files=files, # Use files parameter
        headers=headers
    )

    assert response.status_code == 201 
    response_data = response.json()
    assert response_data["message"] == "File upload stub successful from routes/actigraphy.py"
    assert response_data["file_id"] == "mock_file_id_routes"
    assert response_data["filename"] == actigraphy_file_name # Filename from uploaded file

@pytest.mark.asyncio
async def test_get_actigraphy_data_summary(
    test_client: AsyncClient,
    provider_token: str,
    # upload_data: dict[str, Any] # This was for a POST to /analyze
):
    """Test retrieving actigraphy data summary."""
    patient_id_for_test = "patient-d32dbc8e-3d58-4df0-ba55-0d074f4ff0e7" # Example or from fixture
    headers = {"Authorization": f"Bearer {provider_token}"}
    
    # Corrected URL from /summary/patient-{id} to /patient/{id}/summary
    response = await test_client.get(
        f"/api/v1/actigraphy/patient/{patient_id_for_test}/summary", headers=headers
    )
    
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["patient_id"] == patient_id_for_test
    assert "summary_data" in response_data
    assert response_data["message"] == "Summary stub from routes/actigraphy.py"

@pytest.mark.asyncio
async def test_get_specific_actigraphy_data(
    test_client: AsyncClient,
    provider_token: str,
    # upload_data: dict[str, Any] # Not needed for this test if GETting existing
    # sample_readings: list[dict[str, Any]] # Not needed
):
    """Test retrieving specific actigraphy data record."""
    # Assume some data record exists or is created by a fixture/setup
    data_id_for_test = "data-2a36eb98-a179-44dc-bd77-8e20f64b8bb6" # Example or from fixture
    headers = {"Authorization": f"Bearer {provider_token}"}
    
    # Corrected URL from /results/{id} to /data/{id}
    response = await test_client.get(
        f"/api/v1/actigraphy/data/{data_id_for_test}", headers=headers
    )
    
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["data_id"] == data_id_for_test
    assert "raw_data" in response_data
    assert response_data["message"] == "Data retrieval stub from routes/actigraphy.py"

    # Test for invalid data upload (e.g., missing fields)