"""
Integration tests for the XGBoost service API endpoints.

These tests verify the asynchronous interaction between the API routes
defined in xgboost.py and the mocked XGBoostInterface.
"""

import pytest
import uuid
# from httpx import AsyncClient # Use TestClient instead
from fastapi.testclient import TestClient # Import TestClient
from unittest.mock import AsyncMock
from fastapi import FastAPI, status
from typing import Iterator, Any

# Import the interface and service provider AND get_container
from app.core.services.ml.xgboost.interface import XGBoostInterface, ModelType
from app.infrastructure.di.container import get_service, get_container # Import get_container

# Import Schemas (assuming structure from previous context)
from app.presentation.api.schemas.xgboost import (
    RiskPredictionRequest,
    RiskPredictionResponse,
    TreatmentResponseRequest,
    TreatmentResponseResponse,
    OutcomePredictionRequest,
    OutcomePredictionResponse,
    # ModelInfoRequest, # GET request doesn't use a request body schema
    ModelInfoResponse,
    # FeatureImportanceRequest, # GET request doesn't use a request body schema
    FeatureImportanceResponse,
)
# Import Exceptions (assuming structure from previous context)
from app.core.services.ml.xgboost.exceptions import (
    XGBoostServiceError,
    ValidationError,
    ModelNotFoundError,
    PredictionError,
    ResourceNotFoundError
)

# Import the actual router we are testing
from app.presentation.api.v1.endpoints.xgboost import router as xgboost_router

# Import auth dependency for mocking
from app.presentation.api.dependencies.auth import verify_provider_access

# --- Test Fixtures ---

@pytest.fixture(scope="module") # Change scope to module
def mock_xgboost_service():
    """Fixture for a module-scoped AsyncMock XGBoost service interface.""" # Updated docstring
    mock_service = AsyncMock(spec=XGBoostInterface)
    # Configure mock return values
    mock_service.predict_risk.return_value = {"prediction_id": "risk-pred-123", "risk_score": 0.75, "confidence": 0.9, "risk_level": "high"}
    mock_service.predict_treatment_response.return_value = {"prediction_id": "treat-pred-456", "response_probability": 0.8, "confidence": 0.85}
    mock_service.predict_outcome.return_value = {"prediction_id": "outcome-pred-789", "outcome_prediction": "stable", "confidence": 0.92}
    mock_service.get_model_info.return_value = {"model_type": ModelType.RISK_RELAPSE.value, "version": "1.0", "description": "Mock Relapse Model", "features": ["feat1", "feat2"]}
    mock_service.get_feature_importance.return_value = {"prediction_id": "pred123", "feature_importance": {"feat1": 0.6, "feat2": 0.4}}
    mock_service.get_available_models.return_value = [{"model_type": ModelType.RISK_RELAPSE.value, "version": "1.0"}]
    # Ensure the mock has the is_initialized attribute/property expected by the interface
    mock_service.is_initialized = True
    return mock_service

@pytest.fixture(scope="module")
def test_app(mock_xgboost_service: AsyncMock) -> Iterator[FastAPI]: # Inject the actual mock service fixture
    """Fixture to create a test app with the XGBoostInterface dependency overridden."""
    from app.main import app  # Local import
    from app.core.services.ml.xgboost.interface import XGBoostInterface # Import the interface to override

    # Store original overrides if any (though unlikely for module scope)
    original_overrides = app.dependency_overrides.copy()

    # Override the XGBoostInterface dependency with the mock service
    app.dependency_overrides[XGBoostInterface] = lambda: mock_xgboost_service
    
    # Critical: Override the authentication dependency to bypass security for tests
    # This allows tests to run without real JWT verification
    async def mock_auth():
        # Return a mock authenticated user context
        return {"user_id": "provider-12345", "role": "provider"}
    
    app.dependency_overrides[verify_provider_access] = mock_auth

    yield app # Provide the app with the override active

    # Restore original overrides after the module tests are done
    app.dependency_overrides = original_overrides

@pytest.fixture
def client(test_app):
    """Create a TestClient instance for testing."""
    # Use standard TestClient
    with TestClient(app=test_app) as test_client:
        yield test_client

# --- Async Integration Tests (using TestClient) ---

@pytest.mark.asyncio # Keep this marker for the test function itself
async def test_predict_risk_success(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test successful risk prediction via the async endpoint using TestClient."""
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "risk_type": ModelType.RISK_RELAPSE.value,
        "clinical_data": {"feature1": 10, "feature2": 20.5},
        "time_frame_days": 90
    }
    expected_response_data = mock_xgboost_service.predict_risk.return_value

    # Use the hardcoded mock token string accepted by the async_client fixture's mock auth
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.post("/api/v1/xgboost/predict/risk", json=request_data, headers=auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    # Assert mock was awaited within the endpoint
    mock_xgboost_service.predict_risk.assert_awaited_once_with(
        patient_id=str(patient_id),
        risk_type=ModelType.RISK_RELAPSE.value,
        clinical_data=request_data["clinical_data"],
        time_frame_days=request_data["time_frame_days"]
    )

@pytest.mark.asyncio
async def test_predict_treatment_response_success(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test successful treatment response prediction using TestClient."""
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "treatment_type": ModelType.TREATMENT_MEDICATION_SSRI.value,
        "treatment_details": {"medication": "sertraline", "dosage_mg": 100},
        "clinical_data": {"gad7": 12, "phq9": 14}
    }
    expected_response_data = mock_xgboost_service.predict_treatment_response.return_value

    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.post("/api/v1/xgboost/predict/treatment-response", json=request_data, headers=auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.predict_treatment_response.assert_awaited_once_with(
        patient_id=str(patient_id),
        treatment_type=ModelType.TREATMENT_MEDICATION_SSRI.value,
        treatment_details=request_data["treatment_details"],
        clinical_data=request_data["clinical_data"]
    )

@pytest.mark.asyncio
async def test_predict_outcome_success(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test successful outcome prediction using TestClient."""
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "outcome_timeframe": {"weeks": 12},
        "clinical_data": {"baseline_severity": "moderate", "comorbidities": ["anxiety"]},
        "treatment_plan": {"therapy": "CBT", "medication": "none"}
    }
    expected_response_data = mock_xgboost_service.predict_outcome.return_value

    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.post("/api/v1/xgboost/predict/outcome", json=request_data, headers=auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.predict_outcome.assert_awaited_once_with(
        patient_id=str(patient_id),
        outcome_timeframe=request_data["outcome_timeframe"],
        clinical_data=request_data["clinical_data"],
        treatment_plan=request_data["treatment_plan"]
    )

@pytest.mark.asyncio
async def test_get_model_info_success(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test successful retrieval of model info using TestClient."""
    model_type = ModelType.RISK_RELAPSE.value
    expected_response_data = mock_xgboost_service.get_model_info.return_value

    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.get(f"/api/v1/xgboost/models/{model_type}/info", headers=auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.get_model_info.assert_awaited_once_with(model_type=model_type)

@pytest.mark.asyncio
async def test_get_feature_importance_success(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test successful retrieval of feature importance using TestClient."""
    prediction_id = "pred123"
    patient_id = uuid.uuid4()
    model_type = ModelType.RISK_RELAPSE.value
    expected_response_data = mock_xgboost_service.get_feature_importance.return_value

    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.get(
        f"/api/v1/xgboost/predictions/{prediction_id}/feature-importance",
        params={"patient_id": str(patient_id), "model_type": model_type},
        headers=auth_headers
    )

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.get_feature_importance.assert_awaited_once_with(
        patient_id=str(patient_id),
        model_type=model_type,
        prediction_id=prediction_id
    )

# --- Error Handling Tests (Example using TestClient) ---

@pytest.mark.asyncio
async def test_predict_risk_validation_error(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test validation error during risk prediction using TestClient."""
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        # Missing risk_type
        "clinical_data": {"feature1": 10},
        "time_frame_days": 90
    }
    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.post("/api/v1/xgboost/predict/risk", json=request_data, headers=auth_headers)

    # If auth passes (due to mock override), we expect 422 for validation.
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY, f"Response: {response.text}"
    mock_xgboost_service.predict_risk.assert_not_awaited() # Service method shouldn't be called

@pytest.mark.asyncio
async def test_get_model_info_not_found(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test requesting info for a non-existent model type using TestClient."""
    model_type = "non-existent-model"
    # Configure mock to raise ModelNotFoundError
    mock_xgboost_service.get_model_info.side_effect = ModelNotFoundError(f"Model type '{model_type}' not found.")

    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.get(f"/api/v1/xgboost/models/{model_type}/info", headers=auth_headers)

    assert response.status_code == status.HTTP_404_NOT_FOUND, f"Response: {response.text}"
    assert "not found" in response.json().get("detail", "").lower()
    mock_xgboost_service.get_model_info.assert_awaited_once_with(model_type=model_type)
    # Reset side effect if mock service is reused
    mock_xgboost_service.get_model_info.side_effect = None

@pytest.mark.asyncio
async def test_service_unavailable(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test handling of service errors using TestClient."""
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "risk_type": ModelType.RISK_RELAPSE.value,
        "clinical_data": {"feature1": 10, "feature2": 20.5},
        "time_frame_days": 90
    }
    # Configure mock to raise XGBoostServiceError
    mock_xgboost_service.predict_risk.side_effect = XGBoostServiceError("Underlying service failed.")

    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.post("/api/v1/xgboost/predict/risk", json=request_data, headers=auth_headers)

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE, f"Response: {response.text}"
    assert "service unavailable" in response.json().get("detail", "").lower()
    # Reset side effect if mock service is reused
    mock_xgboost_service.predict_risk.side_effect = None

# --- Additional Test Cases ---

@pytest.mark.asyncio
async def test_get_feature_importance_not_found(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test requesting feature importance for a non-existent prediction ID."""
    prediction_id = "non-existent-pred"
    patient_id = uuid.uuid4()
    model_type = ModelType.RISK_RELAPSE.value
    # Configure mock to raise ResourceNotFoundError
    mock_xgboost_service.get_feature_importance.side_effect = ResourceNotFoundError(f"Prediction '{prediction_id}' not found.")

    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Call TestClient synchronously with correct headers
    response = client.get(
        f"/api/v1/xgboost/predictions/{prediction_id}/feature-importance",
        params={"patient_id": str(patient_id), "model_type": model_type},
        headers=auth_headers
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND, f"Response: {response.text}"
    assert "not found" in response.json().get("detail", "").lower()
    mock_xgboost_service.get_feature_importance.assert_awaited_once_with(
        patient_id=str(patient_id),
        model_type=model_type,
        prediction_id=prediction_id
    )
    # Reset side effect
    mock_xgboost_service.get_feature_importance.side_effect = None

@pytest.mark.asyncio
async def test_integrate_with_digital_twin_success(client: TestClient, mock_xgboost_service: AsyncMock): # Removed provider_token_headers injection
    """Test successful integration with digital twin."""
    # Simulate getting a prediction ID from a previous call
    prediction_id = "risk-pred-integrate"
    patient_id = uuid.uuid4()
    # Mock the get_prediction method if it's used by the integration logic
    # For simplicity, assume integration uses prediction_id directly
    # mock_xgboost_service.get_prediction.return_value = {...} 
    
    integration_payload = {
        "prediction_id": prediction_id,
        "patient_id": str(patient_id)
    }
    # Mock the integration method if XGBoostInterface has one
    # mock_xgboost_service.integrate_with_digital_twin.return_value = {"integration_status": "success", "updated_profile": {...}}
    expected_integration_response = {"message": "Integration successful", "patient_id": str(patient_id)}
    # Assume the endpoint returns a simple success message for now

    # Use the hardcoded mock token string
    auth_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    # Make the POST request to the integration endpoint
    response = client.post("/api/v1/xgboost/integrate-digital-twin", json=integration_payload, headers=auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_integration_response
    # Add assertion for mock call if integrate_with_digital_twin exists
    # mock_xgboost_service.integrate_with_digital_twin.assert_awaited_once_with(...) 

# Add tests for unauthorized access (missing or invalid token)
@pytest.mark.asyncio
async def test_predict_risk_unauthorized(client: TestClient, mock_xgboost_service: AsyncMock):
    """Test accessing predict risk endpoint without valid authentication."""
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "risk_type": ModelType.RISK_RELAPSE.value,
        "clinical_data": {"feature1": 10},
        "time_frame_days": 90
    }
    # No auth headers provided
    response = client.post("/api/v1/xgboost/predict/risk", json=request_data)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Response: {response.text}"
    mock_xgboost_service.predict_risk.assert_not_awaited()
