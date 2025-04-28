"""
Integration tests for the XGBoost service API endpoints.

These tests verify the asynchronous interaction between the API routes
defined in xgboost.py and the mocked XGBoostInterface.
"""

import pytest
import uuid
from httpx import AsyncClient # Use TestClient instead
from fastapi.testclient import TestClient # Import TestClient
from unittest.mock import AsyncMock
from fastapi import FastAPI, status
from typing import Iterator, Any, Dict
from unittest.mock import patch

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

# Import the function to be patched
from app.infrastructure.security.rate_limiting.rate_limiter import get_rate_limiter

# Import the middleware class to patch
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware

# --- Test Fixtures ---

# Client fixture now uses async_client from conftest.py
@pytest.fixture
def client(async_client: AsyncClient):
    """Provides the httpx.AsyncClient configured globally in conftest.py."""
    return async_client

# --- Async Integration Tests ---

@pytest.mark.asyncio
async def test_predict_risk_success(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    """Test successful risk prediction.
       XGBoostInterface override is now handled globally in conftest.py async_client fixture.
    """
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "risk_type": ModelType.RISK_RELAPSE.value,
        "clinical_data": {"feature1": 10, "feature2": 20.5},
        "time_frame_days": 90
    }
    expected_response_data = mock_xgboost_service.predict_risk.return_value
    # Use real auth headers from fixture
    response = await client.post("/api/v1/xgboost/predict/risk", json=request_data, headers=provider_auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.predict_risk.assert_awaited_once_with(
        patient_id=str(patient_id),
        risk_type=ModelType.RISK_RELAPSE.value,
        clinical_data=request_data["clinical_data"],
        time_frame_days=request_data["time_frame_days"]
    )

@pytest.mark.asyncio
async def test_predict_treatment_response_success(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "treatment_type": ModelType.TREATMENT_MEDICATION_SSRI.value,
        "treatment_details": {"medication": "sertraline", "dosage_mg": 100},
        "clinical_data": {"gad7": 12, "phq9": 14}
    }
    expected_response_data = mock_xgboost_service.predict_treatment_response.return_value
    # Use real auth headers from fixture
    response = await client.post("/api/v1/xgboost/predict/treatment-response", json=request_data, headers=provider_auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.predict_treatment_response.assert_awaited_once_with(
        patient_id=str(patient_id),
        treatment_type=ModelType.TREATMENT_MEDICATION_SSRI.value,
        treatment_details=request_data["treatment_details"],
        clinical_data=request_data["clinical_data"]
    )

@pytest.mark.asyncio
async def test_predict_outcome_success(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "outcome_timeframe": {"weeks": 12},
        "clinical_data": {"baseline_severity": "moderate", "comorbidities": ["anxiety"]},
        "treatment_plan": {"therapy": "CBT", "medication": "none"}
    }
    expected_response_data = mock_xgboost_service.predict_outcome.return_value
    # Use real auth headers from fixture
    response = await client.post("/api/v1/xgboost/predict/outcome", json=request_data, headers=provider_auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.predict_outcome.assert_awaited_once_with(
        patient_id=str(patient_id),
        outcome_timeframe=request_data["outcome_timeframe"],
        clinical_data=request_data["clinical_data"],
        treatment_plan=request_data["treatment_plan"]
    )

@pytest.mark.asyncio
async def test_get_model_info_success(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    model_type = ModelType.RISK_RELAPSE.value
    expected_response_data = mock_xgboost_service.get_model_info.return_value
    # Use real auth headers from fixture
    response = await client.get(f"/api/v1/xgboost/models/{model_type}/info", headers=provider_auth_headers)

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.get_model_info.assert_awaited_once_with(model_type=model_type)

@pytest.mark.asyncio
async def test_get_feature_importance_success(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    prediction_id = "pred123"
    patient_id = uuid.uuid4()
    model_type = ModelType.RISK_RELAPSE.value
    expected_response_data = mock_xgboost_service.get_feature_importance.return_value
    # Use real auth headers from fixture
    response = await client.get(
        f"/api/v1/xgboost/predictions/{prediction_id}/feature-importance",
        params={"patient_id": str(patient_id), "model_type": model_type},
        headers=provider_auth_headers
    )

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_response_data
    mock_xgboost_service.get_feature_importance.assert_awaited_once_with(
        patient_id=str(patient_id),
        model_type=model_type,
        prediction_id=prediction_id
    )

@pytest.mark.asyncio
async def test_predict_risk_validation_error(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        # Missing risk_type
        "clinical_data": {"feature1": 10},
        "time_frame_days": 90
    }
    # Use real auth headers from fixture
    response = await client.post("/api/v1/xgboost/predict/risk", json=request_data, headers=provider_auth_headers)

    # If auth passes (due to mock override), we expect 422 for validation.
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY, f"Response: {response.text}"
    mock_xgboost_service.predict_risk.assert_not_awaited() # Service method shouldn't be called

@pytest.mark.asyncio
async def test_get_model_info_not_found(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    model_type = "non-existent-model"
    # Configure mock to raise ModelNotFoundError
    mock_xgboost_service.get_model_info.side_effect = ModelNotFoundError(f"Model type '{model_type}' not found.")

    # Use real auth headers from fixture
    response = await client.get(f"/api/v1/xgboost/models/{model_type}/info", headers=provider_auth_headers)

    assert response.status_code == status.HTTP_404_NOT_FOUND, f"Response: {response.text}"
    assert "not found" in response.json().get("detail", "").lower()
    mock_xgboost_service.get_model_info.assert_awaited_once_with(model_type=model_type)
    # Reset side effect if mock service is reused
    mock_xgboost_service.get_model_info.side_effect = None

@pytest.mark.asyncio
async def test_service_unavailable(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "risk_type": ModelType.RISK_RELAPSE.value,
        "clinical_data": {"feature1": 10, "feature2": 20.5},
        "time_frame_days": 90
    }
    # Configure mock to raise XGBoostServiceError
    mock_xgboost_service.predict_risk.side_effect = XGBoostServiceError("Underlying service failed.")

    # Use real auth headers from fixture
    response = await client.post("/api/v1/xgboost/predict/risk", json=request_data, headers=provider_auth_headers)

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE, f"Response: {response.text}"
    assert "service unavailable" in response.json().get("detail", "").lower()
    # Reset side effect if mock service is reused
    mock_xgboost_service.predict_risk.side_effect = None

@pytest.mark.asyncio
async def test_get_feature_importance_not_found(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    prediction_id = "non-existent-pred"
    patient_id = uuid.uuid4()
    model_type = ModelType.RISK_RELAPSE.value
    # Configure mock to raise ResourceNotFoundError
    mock_xgboost_service.get_feature_importance.side_effect = ResourceNotFoundError(f"Prediction '{prediction_id}' not found.")

    # Use real auth headers from fixture
    response = await client.get(
        f"/api/v1/xgboost/predictions/{prediction_id}/feature-importance",
        params={"patient_id": str(patient_id), "model_type": model_type},
        headers=provider_auth_headers
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
async def test_integrate_with_digital_twin_success(client: AsyncClient, mock_xgboost_service: AsyncMock, provider_auth_headers: Dict[str, str]):
    prediction_id = "risk-pred-integrate"
    patient_id = uuid.uuid4()
    integration_payload = {
        "prediction_id": prediction_id,
        "patient_id": str(patient_id)
    }
    expected_integration_response = {"message": "Integration successful", "patient_id": str(patient_id)}
    mock_xgboost_service.integrate_with_digital_twin.return_value = expected_integration_response

    # Use real auth headers from fixture
    response = await client.post(
        f"/api/v1/xgboost/integrate/{prediction_id}",
        json=integration_payload,
        headers=provider_auth_headers
    )

    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    assert response.json() == expected_integration_response
    mock_xgboost_service.integrate_with_digital_twin.assert_awaited_once_with(
        prediction_id=prediction_id,
        patient_id=str(patient_id)
    )

# New tests to check for 401 Unauthorized without headers
@pytest.mark.asyncio
async def test_predict_risk_no_auth(client: AsyncClient, mock_xgboost_service: AsyncMock):
    patient_id = uuid.uuid4()
    request_data = {
        "patient_id": str(patient_id),
        "risk_type": ModelType.RISK_RELAPSE.value,
        "clinical_data": {"feature1": 10, "feature2": 20.5},
        "time_frame_days": 90
    }
    response = await client.post("/api/v1/xgboost/predict/risk", json=request_data)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Response: {response.text}"
    mock_xgboost_service.predict_risk.assert_not_awaited()

@pytest.mark.asyncio
async def test_get_model_info_no_auth(client: AsyncClient, mock_xgboost_service: AsyncMock):
    model_type = ModelType.RISK_RELAPSE.value
    response = await client.get(f"/api/v1/xgboost/models/{model_type}/info")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Response: {response.text}"
    mock_xgboost_service.get_model_info.assert_not_awaited()

@pytest.mark.asyncio
async def test_get_feature_importance_no_auth(client: AsyncClient, mock_xgboost_service: AsyncMock):
    prediction_id = "pred123"
    patient_id = uuid.uuid4()
    model_type = ModelType.RISK_RELAPSE.value
    response = await client.get(
        f"/api/v1/xgboost/predictions/{prediction_id}/feature-importance",
        params={"patient_id": str(patient_id), "model_type": model_type}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Response: {response.text}"
    mock_xgboost_service.get_feature_importance.assert_not_awaited()
