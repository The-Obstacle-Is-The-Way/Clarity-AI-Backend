from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.services.ml.xgboost.mock import MockXGBoostService
from app.presentation.api.v1.routes.xgboost import router as xgboost_router

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio


# Mock the dependency
async def mock_verify_provider_access() -> dict[str, Any]:
    return {"sub": "test_provider", "scopes": ["xgboost:predict"]}


# Fixture for the mock service instance
@pytest.fixture
def mock_service() -> MockXGBoostService:
    """Create a mock XGBoost service for testing."""
    return MockXGBoostService()


# Refactored test client fixture
@pytest_asyncio.fixture
async def client(mock_service: MockXGBoostService) -> AsyncGenerator[AsyncClient, None]:
    """Provide a test client with mocked dependencies."""
    app = FastAPI()

    # Override the dependency
    from app.presentation.api.dependencies.auth import verify_provider_access
    app.dependency_overrides[verify_provider_access] = mock_verify_provider_access
    from app.presentation.api.v1.routes.xgboost import get_xgboost_service
    app.dependency_overrides[get_xgboost_service] = lambda: mock_service

    # Include the router
    app.include_router(xgboost_router, prefix="/api/v1/xgboost")

    # Create and yield the client
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client_instance:
        yield client_instance


# Define the test class
class TestXGBoostIntegration:
    """Group integration tests for the XGBoost service API."""

    # Ensure tests use the client fixture.
    # Fixtures applied via markers or autouse=True are fine, but explicit is clear.
    # Ensure that the mock_service is correctly passed and used,
    # and the paths match the implemented router. <-- This is now addressed.

    async def test_risk_prediction_flow(self, client: AsyncClient, 
                                      mock_service: MockXGBoostService) -> None:
        """Test the risk prediction workflow."""
        # Configure mock return value
        mock_service.predict_risk = AsyncMock(return_value={
            "prediction_id": "pred_risk_123",
            "risk_score": 0.75,
            "risk_level": "high", 
            "confidence": 0.9,
            "details": "Mock prediction details"
        })

        # Prepare request data matching RiskPredictionRequest
        risk_request = {
            "patient_id": "patient-123",
            "risk_type": "suicide_attempt", # Use valid RiskType enum value
            "patient_data": {
                "age": 40,
                "prior_episodes": 2,
                "severity_score": 7,
                "medication_adherence": 0.8,
            },
            "clinical_data": {
                "age": 40,
                "prior_episodes": 2,
                "severity_score": 7,
                "medication_adherence": 0.8,
            },
        }
        # Make API call to the correct path
        response = await client.post("/api/v1/xgboost/risk-prediction", json=risk_request)

        # Assertions
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["prediction_id"] == "pred_risk_123"
        assert response_data["risk_score"] == 0.75
        assert response_data["risk_level"] == "high"
        assert response_data["confidence"] == 0.9
        # Verify mock was called
        mock_service.predict_risk.assert_called_once_with(
            patient_id="patient-123",
            risk_type="suicide_attempt", # Match the request
            clinical_data=risk_request["clinical_data"],
        )

    async def test_outcome_prediction(self, client: AsyncClient,
                                          mock_service: MockXGBoostService) -> None:
        """Test the outcome prediction workflow."""
        # Configure mock return value for predict_outcome
        mock_service.predict_outcome = AsyncMock(return_value={
            "patient_id": "patient-123",
            "expected_outcomes": [
                {
                    "domain": "depression",
                    "outcome_type": "symptom_reduction",
                    "predicted_value": 0.4,
                    "probability": 0.75,
                    "confidence_interval": [0.32, 0.48]
                }
            ],
            "response_likelihood": "moderate",
            "recommended_therapies": [
                {
                    "therapy_id": "cbt-001",
                    "therapy_name": "Cognitive Behavioral Therapy",
                    "typical_duration": 12,
                    "therapy_type": "psychotherapy",
                    "is_medication": False
                }
            ]
        })

        # Prepare request data for OutcomePredictionRequest
        outcome_request = {
            "patient_id": "patient-123",
            "features": { # Features might differ for outcome vs treatment response
                "age": 40,
                "prior_treatment_success_rate": 0.6,
                "baseline_severity": 8,
                "comorbidities": ["anxiety"],
            },
            "timeframe_days": 90 # Use integer timeframe_days instead of time_frame dict
        }
        # Use the correct path
        response = await client.post("/api/v1/xgboost/outcome-prediction",
                                     json=outcome_request)

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["patient_id"] == "patient-123"
        assert response_data["response_likelihood"] == "moderate"
        assert len(response_data["expected_outcomes"]) == 1
        assert response_data["expected_outcomes"][0]["domain"] == "depression"

        # Verify mock was called with correct arguments matching OutcomePredictionRequest fields
        mock_service.predict_outcome.assert_called_once_with(
            patient_id="patient-123",
            features=outcome_request["features"],
            timeframe_days=outcome_request["timeframe_days"],
            prediction_domains=None, # Default from request schema if not provided
            prediction_types=None, # Default from request schema if not provided
            include_trajectories=False, # Default from request schema if not provided
            include_recommendations=False # Default from request schema if not provided
        )

    # --- Add tests for other endpoints (outcome, model info, etc.) ---
    # Example for model info (assuming endpoint exists in router)
    async def test_model_info_flow(self, client: AsyncClient, 
                                   mock_service: MockXGBoostService) -> None:
        """Test the model information workflow."""
        model_type = "risk-relapse"  
        mock_service.get_model_info = AsyncMock(return_value={
            "model_type": model_type,
            "version": "1.2.0",
            "training_date": datetime.now().isoformat(),
            "performance_metrics": {"auc": 0.85}
        })
        # Correct path based on router
        await client.get(f"/api/v1/xgboost/model-info/{model_type}") # Path adjusted if necessary

    # --- Add healthcheck test if endpoint exists ---
    async def test_healthcheck(self, client: AsyncClient) -> None:
        """Test the healthcheck endpoint."""
        # Assuming healthcheck endpoint exists at /api/v1/xgboost/health
        await client.get("/api/v1/xgboost/health")
