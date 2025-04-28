# -*- coding: utf-8 -*-
"""
Integration tests for the actigraphy API endpoints.

This module tests the interaction between the API endpoints and the PAT service.
It uses FastAPI's TestClient to make requests to the API and validates the responses.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import patch
import pytest
from fastapi import status, FastAPI
from fastapi.testclient import TestClient


# Use create_application factory instead of importing the instance directly
from app.main import create_application
# Import necessary components for testing actigraphy API
# Corrected path
from app.presentation.api.v1.endpoints.actigraphy import get_pat_service
# Assuming actigraphy router import is not needed if using TestClient with main app
# from app.presentation.api.v1.endpoints.actigraphy import router as actigraphy_router
from app.core.services.ml.pat.mock import MockPATService
from app.presentation.api.schemas.actigraphy import (
    AnalysisType,
    DeviceInfo,
    AnalyzeActigraphyRequest,
    AccelerometerReading,
    UploadResponse,
    AnalysisResponse,
)


# Helper function to create sample readings
def create_sample_readings(num_readings: int = 10) -> List[Dict[str, Any]]:
    """Create sample accelerometer readings for testing."""
    start_time = datetime.now() - timedelta(hours=1)
    readings = []

    for i in range(num_readings):
        timestamp = start_time + timedelta(seconds=i * 6)  # 10Hz
        reading = {
            "timestamp": timestamp.isoformat(),
            "x": 0.1 * i,
            "y": 0.2 * i,
            "z": 0.3 * i,
        }
        readings.append(reading)

    return readings


# Mock JWT token authentication (No longer needed if using real headers)
# def mock_validate_token(token: str) -> Dict[str, Any]:
#     """Mock JWT token validation."""
#     return {"sub": "test-user-id", "role": "clinician"}

# def mock_get_current_user_id(payload: Dict[str, Any]) -> str:
#     """Mock get current user ID."""
#     return payload["sub"]


# Mock PAT service for testing
@pytest.fixture
def mock_pat_service():
    """Fixture for a mock PAT service."""
    # Create a mock PAT service with test data
    service = MockPATService()
    # Initialize with some configuration
    service.initialize({"mock_delay_ms": 0})  # No delay in tests for faster execution
    # Store stubbed analyses per patient for retrieval
    analysis_storage: Dict[str, List[Dict[str, Any]]] = {}

    # Add the get_model_info method since it doesn't exist in the mock
    def get_model_info():
        # Return test model info
        return {
            "name": "Test PAT Model",
            "version": "1.0.0-test",
            "capabilities": [
                "activity_analysis",
                "sleep_analysis",
                "gait_analysis",
            ],
            "supported_devices": [
                "fitbit",
                "apple_watch",
                "samsung_galaxy_watch",
            ],
            "developer": "Novamind Test Team",
            "last_updated": "2025-04-01T00:00:00Z",
        }

    # Add the method directly to the instance
    service.get_model_info = get_model_info
    # Stub analyze_actigraphy to return predictable metrics for integration tests
    def stub_analyze_actigraphy(
        patient_id: str,
        readings: List[Dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: Dict[str, Any],
        analysis_types: List[str]
    ) -> Dict[str, Any]:
        analysis_id = "test-analysis-id"
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        # Provide static sleep metrics
        sleep_metrics = {"sleep_efficiency": 0.85}
        # Provide static activity levels
        activity_levels = {
            "sedentary": 0.6,
            "light": 0.3,
            "moderate": 0.08,
            "vigorous": 0.02,
        }
        result = {
            "analysis_id": analysis_id,
            "patient_id": patient_id,
            "timestamp": timestamp,
            "sleep_metrics": sleep_metrics,
            "activity_levels": activity_levels,
        }
        # Record analysis for later retrieval
        analysis_storage.setdefault(patient_id, []).append(result)
        return result
    service.analyze_actigraphy = stub_analyze_actigraphy
    # Stub get_actigraphy_embeddings to return predictable embedding data for integration tests
    def stub_get_actigraphy_embeddings(
        patient_id: str,
        readings: List[Dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float
    ) -> Dict[str, Any]:
        embedding_id = "test-embedding-id"
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        # Create simple data summary
        duration = datetime.fromisoformat(end_time.replace("Z", "+00:00")) - datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        data_summary = {
            "start_time": start_time,
            "end_time": end_time,
            "duration_seconds": duration.total_seconds(),
            "readings_count": len(readings),
            "sampling_rate_hz": sampling_rate_hz,
        }
        embedding = {
            "vector": [0.1] * 8,
            "dimension": 8,
            "model_version": "test-model-v1",
        }
        return {
            "embedding_id": embedding_id,
            "patient_id": patient_id,
            "timestamp": timestamp,
            "data_summary": data_summary,
            "embedding": embedding,
        }
    service.get_actigraphy_embeddings = stub_get_actigraphy_embeddings
    # Stub retrieval of a single analysis by ID
    def stub_get_analysis_by_id(analysis_id: str) -> Dict[str, Any]:
        for pid, analyses in analysis_storage.items():
            for a in analyses:
                if a["analysis_id"] == analysis_id:
                    return a
        raise Exception(f"Analysis not found: {analysis_id}")
    service.get_analysis_by_id = stub_get_analysis_by_id
    # Stub retrieval of patient analyses list
    def stub_get_patient_analyses(patient_id: str, limit: int, offset: int) -> Dict[str, Any]:
        analyses = analysis_storage.get(patient_id, [])
        return {"patient_id": patient_id, "analyses": analyses, "total": len(analyses)}
    service.get_patient_analyses = stub_get_patient_analyses
    return service


@pytest.fixture
def test_app(mock_pat_service) -> FastAPI:
    """Create a test app instance with overridden dependencies using the real application."""
    from app.main import create_application
    from app.presentation.api.v1.endpoints.actigraphy import get_pat_service
    # Removed: from app.presentation.api.dependencies.auth import get_current_user

    # Create the full application
    app_instance = create_application()
    # Override dependencies: use mock PAT service
    app_instance.dependency_overrides[get_pat_service] = lambda: mock_pat_service
    # Removed override for get_current_user
    # app_instance.dependency_overrides[get_current_user] = lambda: {"id": "test-patient-1", "roles": ["clinician"]}
    yield app_instance # Use yield to allow cleanup if necessary

    # Clean up overrides after tests using this fixture are done
    app_instance.dependency_overrides.clear()


@pytest.fixture
def client(test_app: FastAPI) -> TestClient:
    """Fixture to provide a TestClient instance."""
    return TestClient(test_app)


# --- Test Class ---
class TestActigraphyAPI:
    """Test suite for the actigraphy API endpoints."""

    # --- Test Cases ---
    def test_analyze_actigraphy(self, client: TestClient, provider_token_headers: Dict[str, str]):
        """Test successful actigraphy analysis."""
        patient_id = "patient-analyze-1"
        start_time = datetime.now() - timedelta(hours=1)
        end_time = start_time + timedelta(minutes=1)
        readings = create_sample_readings(num_readings=600) # 1 minute at 10Hz

        request_data = {
            "patient_id": patient_id,
            "readings": readings,
            "start_time": start_time.isoformat() + "Z",
            "end_time": end_time.isoformat() + "Z",
            "sampling_rate_hz": 10.0,
            "device_info": {
                "manufacturer": "TestFit",
                "model": "TestModel",
                "firmware_version": "1.0.0",
            },
            "analysis_types": ["sleep", "activity"],
        }

        response = client.post(
            "/api/v1/actigraphy/analyze",
            json=request_data,
            headers=provider_token_headers # Add authentication headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Expected 200, got {response.status_code}. Response: {response.text}"
        response_data = response.json()
        assert response_data["patient_id"] == patient_id
        assert "analysis_id" in response_data
        assert "sleep_metrics" in response_data
        assert "activity_levels" in response_data

    def test_get_embeddings(self, client: TestClient, provider_token_headers: Dict[str, str]):
        """Test successful retrieval of actigraphy embeddings."""
        patient_id = "patient-embed-1"
        start_time = datetime.now() - timedelta(minutes=30)
        end_time = start_time + timedelta(minutes=5)
        readings = create_sample_readings(num_readings=300) # 5 minutes at 10Hz

        request_data = {
            "patient_id": patient_id,
            "readings": readings,
            "start_time": start_time.isoformat() + "Z",
            "end_time": end_time.isoformat() + "Z",
            "sampling_rate_hz": 10.0,
        }

        response = client.post(
            "/api/v1/actigraphy/embeddings",
            json=request_data,
            headers=provider_token_headers # Add authentication headers
        )

        assert response.status_code == status.HTTP_201_CREATED, f"Expected 201, got {response.status_code}. Response: {response.text}"
        response_data = response.json()
        assert response_data["patient_id"] == patient_id
        assert "embedding_id" in response_data
        assert "data_summary" in response_data
        assert "embedding" in response_data
        assert response_data["embedding"]["dimension"] == 8 # Check dimension matches mock

    def test_get_analysis_by_id(
        self, client: TestClient, mock_pat_service: MockPATService, provider_token_headers: Dict[str, str]
    ):
        """Test retrieving a specific analysis result by its ID."""
        # First, create an analysis to retrieve
        patient_id = "patient-retrieve-1"
        analysis_data = mock_pat_service.analyze_actigraphy(
            patient_id=patient_id,
            readings=create_sample_readings(10),
            start_time=(datetime.now() - timedelta(hours=1)).isoformat() + "Z",
            end_time=datetime.now().isoformat() + "Z",
            sampling_rate_hz=10.0,
            device_info={"manufacturer": "Test"},
            analysis_types=["sleep"],
        )
        analysis_id = analysis_data["analysis_id"]

        response = client.get(
            f"/api/v1/actigraphy/analysis/{analysis_id}",
            headers=provider_token_headers # Add authentication headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Expected 200, got {response.status_code}. Response: {response.text}"
        response_data = response.json()
        assert response_data["analysis_id"] == analysis_id
        assert response_data["patient_id"] == patient_id

    def test_get_patient_analyses(
        self, client: TestClient, mock_pat_service: MockPATService, provider_token_headers: Dict[str, str]
    ):
        """Test retrieving all analysis results for a specific patient."""
        patient_id = "patient-list-analyses-1"
        # Create a couple of analyses for this patient
        mock_pat_service.analyze_actigraphy(
            patient_id=patient_id, readings=[], start_time="", end_time="", sampling_rate_hz=1, device_info={}, analysis_types=[]
        )
        mock_pat_service.analyze_actigraphy(
            patient_id=patient_id, readings=[], start_time="", end_time="", sampling_rate_hz=1, device_info={}, analysis_types=[]
        )

        response = client.get(
            f"/api/v1/actigraphy/patient/{patient_id}/analyses",
            params={"limit": 10, "offset": 0},
            headers=provider_token_headers # Add authentication headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Expected 200, got {response.status_code}. Response: {response.text}"
        response_data = response.json()
        assert response_data["patient_id"] == patient_id
        assert len(response_data["analyses"]) == 2
        assert response_data["total"] == 2

    def test_get_model_info(self, client: TestClient, provider_token_headers: Dict[str, str]):
        """Test retrieving information about the underlying PAT model."""
        response = client.get(
            "/api/v1/actigraphy/model/info",
            headers=provider_token_headers # Add authentication headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Expected 200, got {response.status_code}. Response: {response.text}"
        response_data = response.json()
        assert "name" in response_data
        assert "version" in response_data
        assert "capabilities" in response_data

    def test_integrate_with_digital_twin(
        self, client: TestClient, mock_pat_service: MockPATService, provider_token_headers: Dict[str, str]
    ):
        """Test integrating actigraphy analysis results with the digital twin service."""
        # Create an analysis first
        patient_id = "patient-integrate-dt-1"
        analysis_data = mock_pat_service.analyze_actigraphy(
            patient_id=patient_id, readings=[], start_time="", end_time="", sampling_rate_hz=1, device_info={}, analysis_types=[]
        )
        analysis_id = analysis_data["analysis_id"]

        # Mock the digital twin integration function if it's called directly
        # For now, assume it's handled within the service/use case layer
        # and we just test the API endpoint call
        with patch("app.presentation.api.v1.endpoints.actigraphy.integrate_analysis_with_twin") as mock_integrate:
            mock_integrate.return_value = {"status": "success", "twin_update_id": "dt-update-123"}

            response = client.post(
                f"/api/v1/actigraphy/analysis/{analysis_id}/integrate",
                json={"digital_twin_id": "dt-123"}, # Assuming payload structure
                headers=provider_token_headers # Add authentication headers
            )

            assert response.status_code == status.HTTP_200_OK, f"Expected 200, got {response.status_code}. Response: {response.text}"
            response_data = response.json()
            assert response_data["status"] == "success"
            assert response_data["twin_update_id"] == "dt-update-123"
            # Assert that the mock integration function was called
            mock_integrate.assert_called_once()


    # Note: This test might now fail differently if authentication is required
    # It should return 401 if no headers are provided, or 403 if invalid role.
    # We keep it to test the absence of valid headers.
    def test_unauthorized_access(self, client: TestClient):
        """Test accessing endpoints without proper authentication headers."""
        response = client.post("/api/v1/actigraphy/analyze", json={})
        # Expect 401 Unauthorized if the middleware runs and finds no token
        assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Expected 401, got {response.status_code}. Response: {response.text}"

        response = client.get("/api/v1/actigraphy/analysis/some-id")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Expected 401, got {response.status_code}. Response: {response.text}"

        response = client.get("/api/v1/actigraphy/model/info")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Expected 401, got {response.status_code}. Response: {response.text}"
