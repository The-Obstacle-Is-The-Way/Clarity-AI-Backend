"""
Unit tests for the actigraphy API routes.

This module contains unit tests for the actigraphy API routes, verifying that they
correctly handle requests, responses, and errors.
"""

from datetime import datetime, timedelta
from typing import Any  # Added Optional
from unittest.mock import AsyncMock, MagicMock  # Added AsyncMock

import pytest
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.testclient import TestClient

from app.core.services.ml.pat.exceptions import (
    AnalysisError,
    AuthorizationError,
    EmbeddingError,
    ResourceNotFoundError,
    ValidationError,
)

# Assuming PATInterface and other dependencies exist
from app.core.services.ml.pat.interface import PATInterface
from app.domain.utils.datetime_utils import UTC
from app.presentation.api.schemas.actigraphy import AnalysisType
# from app.presentation.api.v1.routes.actigraphy import router # TODO: Restore when actigraphy route exists

# Assuming auth dependencies exist
# from app.api.dependencies.auth import validate_jwt, get_current_user_id
# from app.api.dependencies.ml import get_pat_service


# Mock data
@pytest.fixture
def mock_token() -> str:

    """Create a mock JWT token."""
    # This is just a placeholder, actual token validation is mocked
#     return "mock_jwt_token"@pytest.fixture
    def patient_id() -> str:

        """Create a mock patient ID."""

        return "patient123"

@pytest.fixture
def sample_readings() -> list[dict[str, Any]]:
    """Create sample accelerometer readings."""
    base_time = datetime.now(UTC)  # Use UTC
    readings = []

    for i in range(10):
        timestamp = (base_time + timedelta(seconds=i / 10)).isoformat() + "Z"
        reading = {
            "timestamp": timestamp,
            "x": 0.1 * i,
            "y": 0.2 * i,
            "z": 0.3 * i,
            "heart_rate": 60 + i,  # Added example heart rate
            "metadata": {"activity": "walking" if i % 2 == 0 else "sitting"},
        }
        readings.append(reading)

    return readings


@pytest.fixture
def device_info() -> dict[str, Any]:
    """Create sample device info."""
    
    return {
        "device_type": "smartwatch",
        "model": "Apple Watch Series 9",
        "manufacturer": "Apple",
        "firmware_version": "1.2.3",
        "position": "wrist_left",  # Added example position
        "metadata": {"battery_level": 85},
    }


@pytest.fixture
def analysis_request(
    patient_id: str, sample_readings: list[dict[str, Any]], device_info: dict[str, Any]
) -> dict[str, Any]:
    """Create an analysis request."""

    return {
        "patient_id": patient_id,
        "readings": sample_readings,
        "start_time": datetime.now(UTC).isoformat() + "Z",
        "end_time": (datetime.now(UTC) + timedelta(hours=1)).isoformat() + "Z",
        "sampling_rate_hz": 10.0,
        "device_info": device_info,
        "analysis_types": [AnalysisType.ACTIVITY, AnalysisType.SLEEP, AnalysisType.STRESS],
        "metadata": {"source": "test"}
    }


@pytest.fixture
def embedding_request(
    patient_id: str, sample_readings: list[dict[str, Any]]
) -> dict[str, Any]:
    """Create an embedding request."""

    return {
        "patient_id": patient_id,
        "readings": sample_readings,
        "start_time": datetime.now(UTC).isoformat() + "Z",
        "end_time": (datetime.now(UTC) + timedelta(hours=1)).isoformat() + "Z",
        "sampling_rate_hz": 10.0,
    }


@pytest.fixture
def integration_request(patient_id: str) -> dict[str, Any]:
    """Create an integration request."""

    return {
        "patient_id": patient_id,
        "profile_id": "profile123",
        "analysis_id": "analysis123"
    }


@pytest.fixture
def analysis_result(
    patient_id: str, device_info: dict[str, Any]
) -> dict[str, Any]:
    """Create an analysis result."""
    now_iso = datetime.now(UTC).isoformat() + "Z"
    end_iso = (datetime.now(UTC) + timedelta(hours=1)).isoformat() + "Z"
    return {
        "analysis_id": "analysis123",
        "patient_id": patient_id,
        "timestamp": now_iso,
        "analysis_types": [AnalysisType.ACTIVITY_LEVEL.value, AnalysisType.SLEEP.value],
        "device_info": device_info,
        "data_summary": {
            "start_time": now_iso,
            "end_time": end_iso,
            "duration_seconds": 3600.0,
            "readings_count": 10,
            "sampling_rate_hz": 10.0,
        },
        "results": {
            AnalysisType.ACTIVITY_LEVEL.value: {
                "activity_levels": {
                    "sedentary": {"percentage": 0.6, "duration_seconds": 2160.0},
                    "light": {"percentage": 0.3, "duration_seconds": 1080.0},
                    "moderate": {"percentage": 0.08, "duration_seconds": 288.0},
                    "vigorous": {"percentage": 0.02, "duration_seconds": 72.0},
                },
                "step_count": 5000,
                "calories_burned": 1200,
                "distance_km": 3.5,
                "avg_heart_rate_bpm": 72,
            },
            AnalysisType.SLEEP.value: {
                "sleep_stages": {
                    "awake": {"percentage": 0.1, "duration_seconds": 360.0},
                    "light": {"percentage": 0.5, "duration_seconds": 1800.0},
                    "deep": {"percentage": 0.3, "duration_seconds": 1080.0},
                    "rem": {"percentage": 0.1, "duration_seconds": 360.0},
                },
                "sleep_efficiency": 0.9,
                "sleep_latency_seconds": 600,
                "interruptions_count": 2,
                "avg_heart_rate_bpm": 55,
                "respiratory_rate_bpm": 14.5,
            },
        },
    }


@pytest.fixture
def embedding_result(patient_id: str) -> dict[str, Any]:
    """Create an embedding result with legacy alias fields."""
    now_iso = datetime.now(UTC).isoformat() + "Z"
    end_iso = (datetime.now(UTC) + timedelta(hours=1)).isoformat() + "Z"
    embedding = {
        "vector": [0.1, 0.2, 0.3, 0.4, 0.5],
        "dimension": 5,
        "model_version": "mock-embedding-v1.0",
    }
    result = {
        "embedding_id": "embedding123",
        "patient_id": patient_id,
        "timestamp": now_iso,
        "data_summary": {
            "start_time": now_iso,
            "end_time": end_iso,
            "duration_seconds": 3600.0,
            "readings_count": 10,
            "sampling_rate_hz": 10.0,
        },
        "embedding": embedding,
        # Legacy aliases
        "embeddings": embedding["vector"],
        "embedding_size": embedding["dimension"],
    }
    return result


@pytest.fixture
def integration_result(patient_id: str) -> dict[str, Any]:
    """Create an integration result."""
    now_iso = datetime.now(UTC).isoformat() + "Z"
    return {
        "integration_id": "integration123",
        "patient_id": patient_id,
        "profile_id": "profile123",
        "analysis_id": "analysis123",
        "timestamp": now_iso,
        "status": "success",
        "insights": [
            {
                "type": "activity_pattern",
                "description": "Daily activity levels show a predominantly sedentary pattern",
                "recommendation": "Consider incorporating more light activity throughout the day",
                "confidence": 0.85,
            },
            {
                "type": "sleep_quality",
                "description": "Sleep efficiency suggests suboptimal rest quality",
                "recommendation": "Consistent sleep schedule and improved sleep hygiene may be beneficial",
                "confidence": 0.9,
            },
        ],
        "profile_update": {
            "updated_aspects": [
                "physical_activity_patterns",
                "sleep_patterns",
                "behavioral_patterns",
            ],
            "confidence_score": 0.92,
            "updated_at": now_iso,
        },
    }


@pytest.fixture
def model_info() -> dict[str, Any]:
    """Create model info."""
    return {
        "name": "MockPAT",
        "version": "1.0.0",
        "description": "Mock implementation of the PAT service for testing",
        "capabilities": [
            "activity_level_analysis",
            "sleep_analysis",
            "gait_analysis",
            "tremor_analysis",
            "embedding_generation"
        ],
        "maintainer": "Concierge Psychiatry Platform Team",
        "last_updated": "2025-03-28",
        "active": True
    }


@pytest.fixture
def analyses_list(patient_id: str) -> dict[str, Any]:
    """Create a list of analyses."""
    now_iso = datetime.now(UTC).isoformat() + "Z"
    yesterday_iso = (datetime.now(UTC) - timedelta(days=1)).isoformat() + "Z"
    yesterday_end_iso = (datetime.now(UTC) - timedelta(days=1) + timedelta(hours=1)).isoformat() + "Z"
    now_end_iso = (datetime.now(UTC) + timedelta(hours=1)).isoformat() + "Z"
    
    return {
        "analyses": [
            {
                "analysis_id": "analysis123",
                "timestamp": now_iso,
                "analysis_types": [
                    AnalysisType.ACTIVITY_LEVEL.value,
                    AnalysisType.SLEEP.value
                ],
                "data_summary": {
                    "start_time": now_iso,
                    "end_time": now_end_iso,
                    "duration_seconds": 3600.0,
                    "readings_count": 10,
                    "sampling_rate_hz": 10.0
                }
            },
            {
                "analysis_id": "analysis456",
                "timestamp": yesterday_iso,
                "analysis_types": [
                    AnalysisType.ACTIVITY_LEVEL.value
                ],
                "data_summary": {
                    "start_time": yesterday_iso,
                    "end_time": yesterday_end_iso,
                    "duration_seconds": 3600.0,
                    "readings_count": 10,
                    "sampling_rate_hz": 10.0
                }
            }
        ],
        "pagination": {
            "total": 2,
            "limit": 10,
            "offset": 0,
            "has_more": False
        }
    }


# Mock PAT service
@pytest.fixture
def mock_pat_service(
    analysis_result: dict[str, Any],
    embedding_result: dict[str, Any],
    integration_result: dict[str, Any],
    model_info: dict[str, Any],
    analyses_list: dict[str, Any],
) -> MagicMock:
    """Create a mock PAT service."""
    mock_service = AsyncMock(spec=PATInterface)  # Use AsyncMock for async methods

    # Add mock settings needed for potential JWT interactions via dependencies
    mock_service.settings = MagicMock()
    mock_service.settings.JWT_SECRET_KEY = "test-secret"
    mock_service.settings.JWT_ALGORITHM = "HS256"
    mock_service.settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
    mock_service.settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7 # Corrected attribute name
    mock_service.settings.JWT_ISSUER = "test-issuer"
    mock_service.settings.JWT_AUDIENCE = "test-audience"

    # Mock methods
    mock_service.analyze_actigraphy = AsyncMock(return_value=analysis_result)
    mock_service.get_actigraphy_embeddings = AsyncMock(return_value=embedding_result)
    mock_service.get_analysis_by_id = AsyncMock(return_value=analysis_result)
    mock_service.get_patient_analyses = AsyncMock(return_value=analyses_list)
    mock_service.get_model_info = AsyncMock(return_value=model_info)
    mock_service.integrate_with_digital_twin = AsyncMock(return_value=integration_result)

    # Synchronous call for analysis types – the route does *not* await it.
    mock_service.get_analysis_types = MagicMock(
        return_value=[t.value for t in AnalysisType]
    )
    
    return mock_service


@pytest.fixture
def app(mock_pat_service):

    """Create FastAPI app instance and override dependencies."""
    app_instance = FastAPI()

    # Mock auth dependencies (replace with actual dependency paths)
    def mock_validate_jwt(token: str | None = None):
        if token != "mock_jwt_token":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return {"sub": "patient123"}  # Return mock payload

    def mock_get_current_user_id(payload: dict = Depends(mock_validate_jwt)):
        return payload.get("sub")
    
    try:
        from app.presentation.api.dependencies.auth import get_current_user_id as actual_get_user_id
        from app.presentation.api.dependencies.auth import validate_jwt as actual_validate_jwt
        
        app_instance.dependency_overrides[actual_validate_jwt] = lambda: mock_validate_jwt
        app_instance.dependency_overrides[actual_get_user_id] = mock_get_current_user_id
    except ImportError:
        print("Warning: Auth dependencies not found for override.")
        pass
        
    # Mock PAT service dependency
    try:
        from app.presentation.api.dependencies.services import (
            get_pat_service as actual_get_pat_service,
        )
        
        app_instance.dependency_overrides[actual_get_pat_service] = lambda: mock_pat_service
    except ImportError:
        print("Warning: get_pat_service dependency not found for override.")
        pass
        
    # app_instance.include_router(router, prefix="/api/v1/actigraphy")  # Add prefix if needed
    
    return app_instance


@pytest.fixture
def client(app):

    """Create TestClient."""
    return TestClient(app)


@pytest.mark.db_required()  # Assuming db_required is a valid marker
class TestActigraphyRoutes:
    """Tests for the actigraphy API routes."""
    
    def test_analyze_actigraphy_success(
        self,
        client: TestClient,
        mock_token: str,
        analysis_request: dict[str, Any],
        analysis_result: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test successful actigraphy analysis."""
        # Make the request
        response = client.post(
            "/api/v1/actigraphy/analyze",  # Added prefix
            json=analysis_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        
        # Check the response
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json() == analysis_result
        
        # Verify service call
        mock_pat_service.analyze_actigraphy.assert_called_once()

    def test_analyze_actigraphy_unauthorized(
        self, client: TestClient, mock_token: str, analysis_request: dict[str, Any]
    ) -> None:
        """Test unauthorized actigraphy analysis."""
        # Change patient ID to trigger authorization error (assuming auth checks this)
        modified_request = analysis_request.copy()
        modified_request["patient_id"] = "different_patient"

        # Make the request
        response = client.post(
            "/api/v1/actigraphy/analyze",  # Added prefix
            json=modified_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        
        # Check the response (depends on how auth is implemented)
        # If auth checks patient_id against token 'sub', this should fail
        # Assuming a 403 Forbidden if patient_id doesn't match user_id
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Not authorized" in response.json()["detail"]

    def test_analyze_actigraphy_validation_error(
        self,
        client: TestClient,
        mock_token: str,
        analysis_request: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test actigraphy analysis with validation error."""
        # Setup the mock to raise a validation error
        mock_pat_service.analyze_actigraphy.side_effect = ValidationError("Invalid input")
        
        # Make the request
        response = client.post(
            "/api/v1/actigraphy/analyze",  # Added prefix
            json=analysis_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        
        # Check the response
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "Invalid input" in response.json()["detail"]

    def test_analyze_actigraphy_analysis_error(
        self,
        client: TestClient,
        mock_token: str,
        analysis_request: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test actigraphy analysis with analysis error."""
        # Setup the mock to raise an analysis error
        mock_pat_service.analyze_actigraphy.side_effect = AnalysisError("Analysis failed")
        
        # Make the request
        response = client.post(
            "/api/v1/actigraphy/analyze",  # Added prefix
            json=analysis_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        
        # Check the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "Analysis failed" in response.json()["detail"]

    def test_get_actigraphy_embeddings_success(
        self,
        client: TestClient,
        mock_token: str,
        embedding_request: dict[str, Any],
        embedding_result: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test successful embedding generation."""
        # Make the request
        response = client.post(
            "/api/v1/actigraphy/embeddings",  # Added prefix
            json=embedding_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )

        # Check the response
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json() == embedding_result
        
        # Verify service call
        mock_pat_service.get_actigraphy_embeddings.assert_called_once()

    def test_get_actigraphy_embeddings_unauthorized(
        self, client: TestClient, mock_token: str, embedding_request: dict[str, Any]
    ) -> None:
        """Test unauthorized embedding generation."""
        # Change patient ID to trigger authorization error
        modified_request = embedding_request.copy()
        modified_request["patient_id"] = "different_patient"

        # Make the request
        response = client.post(
            "/api/v1/actigraphy/embeddings",  # Added prefix
            json=modified_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        
        # Check the response
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Not authorized" in response.json()["detail"]

    def test_get_actigraphy_embeddings_validation_error(
        self,
        client: TestClient,
        mock_token: str,
        embedding_request: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test embedding generation with validation error."""
        # Setup the mock to raise a validation error
        mock_pat_service.get_actigraphy_embeddings.side_effect = ValidationError("Invalid input")

        # Make the request
        response = client.post(
            "/api/v1/actigraphy/embeddings",  # Added prefix
            json=embedding_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
    
        # Check the response
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "Invalid input" in response.json()["detail"]

    def test_get_actigraphy_embeddings_embedding_error(
        self,
        client: TestClient,
        mock_token: str,
        embedding_request: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test embedding generation with embedding error."""
        # Setup the mock to raise an embedding error
        mock_pat_service.get_actigraphy_embeddings.side_effect = EmbeddingError("Embedding failed")

        # Make the request
        response = client.post(
            "/api/v1/actigraphy/embeddings",  # Added prefix
            json=embedding_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
    
        # Check the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "Embedding failed" in response.json()["detail"]

    def test_get_analysis_by_id_success(
        self,
        client: TestClient,
        mock_token: str,
        analysis_result: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test successful analysis retrieval."""
        analysis_id = analysis_result["analysis_id"]
        # Make the request
        response = client.get(
            f"/api/v1/actigraphy/analyses/{analysis_id}",  # Added prefix
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        
        # Check the response
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == analysis_result
        
        # Verify service call
        mock_pat_service.get_analysis_by_id.assert_called_once_with(analysis_id)

    def test_get_analysis_by_id_not_found(
        self, client: TestClient, mock_token: str, mock_pat_service: MagicMock
    ) -> None:
        """Test analysis retrieval with not found error."""
        analysis_id = "nonexistent-analysis"
        # Setup the mock to raise ResourceNotFoundError
        mock_pat_service.get_analysis_by_id.side_effect = ResourceNotFoundError("Analysis not found")

        # Make the request
        response = client.get(
            f"/api/v1/actigraphy/analyses/{analysis_id}",  # Added prefix
            headers={"Authorization": f"Bearer {mock_token}"}
        )
    
        # Check the response
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "Analysis not found" in response.json()["detail"]

    def test_get_analysis_by_id_unauthorized(
        self,
        client: TestClient,
        mock_token: str,
        analysis_result: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test unauthorized analysis retrieval."""
        analysis_id = analysis_result["analysis_id"]
        # Setup the mock to raise AuthorizationError
        mock_pat_service.get_analysis_by_id.side_effect = AuthorizationError("Not authorized")
        
        # Make the request
        response = client.get(
            f"/api/v1/actigraphy/analyses/{analysis_id}",  # Added prefix
            headers={"Authorization": f"Bearer {mock_token}"}
        )
    
        # Check the response
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Not authorized" in response.json()["detail"]

    def test_get_patient_analyses_success(
        self,
        client: TestClient,
        mock_token: str,
        patient_id: str,
        analyses_list: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test successful patient analyses retrieval."""
        # Make the request to the correct endpoint
        response = client.get(
            f"/api/v1/actigraphy/patient/{patient_id}/analyses",
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        # Check the response status
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Validate structured response
        assert data.get("patient_id") == patient_id
        assert "analyses" in data and isinstance(data.get("analyses"), list)
        assert data.get("total") == len(data.get("analyses"))
        # Verify service call with default pagination
        mock_pat_service.get_patient_analyses.assert_called_once_with(
            patient_id=patient_id, limit=10, offset=0
        )
    

    def test_get_patient_analyses_unauthorized(
        self, client: TestClient, mock_token: str, patient_id: str
    ) -> None:
        """Test unauthorized patient analyses retrieval."""
        # Make the request for a different patient ID
        response = client.get(
            "/api/v1/actigraphy/patient/different_patient/analyses",
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        # Expect forbidden status
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Not authorized" in response.json().get("detail", "")

    def test_get_model_info_success(
        self,
        client: TestClient,
        mock_token: str,
        model_info: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test successful model info retrieval."""
        # Make the request
        response = client.get(
            "/api/v1/actigraphy/model-info",  # Added prefix
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        

        # Check the response

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == model_info

        # Verify service call
        mock_pat_service.get_model_info.assert_called_once()

    def test_integrate_with_digital_twin_success(
        self,
        client: TestClient,
        mock_token: str,
        integration_request: dict[str, Any],
        integration_result: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test successful digital twin integration."""
        # Make the request
        response = client.post(
            "/api/v1/actigraphy/integrate",  # Added prefix
            json=integration_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        
        # Check the response

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == integration_result

        # Verify service call
        mock_pat_service.integrate_with_digital_twin.assert_called_once()

    def test_get_analysis_types_success(
        self,
        client: TestClient,
        mock_pat_service: MagicMock,
    ) -> None:
        """Test retrieving the list of available analysis types."""

        expected = [t.value for t in AnalysisType]

        response = client.get("/api/v1/actigraphy/analysis_types")

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == expected

        mock_pat_service.get_analysis_types.assert_called_once()

    def test_integrate_with_digital_twin_unauthorized(
        self, client: TestClient, mock_token: str, integration_request: dict[str, Any]
    ) -> None:
        """Test unauthorized digital twin integration."""
        # Change patient ID
        modified_request = integration_request.copy()
        modified_request["patient_id"] = "different_patient"

        # Make the request
        response = client.post(
            "/api/v1/actigraphy/integrate",  # Added prefix
            json=modified_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )

        # Check the response
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Not authorized" in response.json()["detail"]

    def test_integrate_with_digital_twin_not_found(
        self,
        client: TestClient,
        mock_token: str,
        integration_request: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test digital twin integration with not found error."""
        # Setup mock to raise error
        mock_pat_service.integrate_with_digital_twin.side_effect = ResourceNotFoundError("Analysis not found")
        
        # Make the request
        response = client.post(
            "/api/v1/actigraphy/integrate",  # Added prefix
            json=integration_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
    
        # Check the response
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "Analysis not found" in response.json()["detail"]

    def test_integrate_with_digital_twin_authorization_error(
        self,
        client: TestClient,
        mock_token: str,
        integration_request: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test digital twin integration with authorization error."""
        # Setup mock to raise error
        mock_pat_service.integrate_with_digital_twin.side_effect = AuthorizationError("Integration not allowed")

        # Make the request
        response = client.post(
            "/api/v1/actigraphy/integrate",  # Added prefix
            json=integration_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
    
        # Check the response
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Integration not allowed" in response.json()["detail"]

    def test_integrate_with_digital_twin_validation_error(
        self,
        client: TestClient,
        mock_token: str,
        integration_request: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test digital twin integration with validation error."""
        # Setup mock to raise error
        mock_pat_service.integrate_with_digital_twin.side_effect = ValidationError("Invalid profile ID")

        # Make the request
        response = client.post(
            "/api/v1/actigraphy/integrate",  # Added prefix
            json=integration_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
    
        # Check the response
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "Invalid profile ID" in response.json()["detail"]

    def test_integrate_with_digital_twin_integration_error(
        self,
        client: TestClient,
        mock_token: str,
        integration_request: dict[str, Any],
        mock_pat_service: MagicMock,
    ) -> None:
        """Test digital twin integration with integration error."""
        # Setup mock to raise error
        mock_pat_service.integrate_with_digital_twin.side_effect = Exception("Integration failed")  # Generic exception

        # Make the request
        response = client.post(
            "/api/v1/actigraphy/integrate",  # Added prefix
            json=integration_request,
            headers={"Authorization": f"Bearer {mock_token}"}
        )
        
        # Check the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "Integration failed" in response.json()["detail"]
