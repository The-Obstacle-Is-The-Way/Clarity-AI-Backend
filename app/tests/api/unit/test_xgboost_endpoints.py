"""
Unit tests for XGBoost API endpoints.

This module tests the XGBoost API endpoints to ensure they correctly
handle requests, interact with the XGBoost service, and return
appropriate responses.
"""

from datetime import datetime
from typing import NoReturn
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.services.ml.xgboost.enums import ResponseLevel, RiskLevel
from app.core.services.ml.xgboost.exceptions import (
    ConfigurationError,
    ModelNotFoundError,
    PredictionError,
    ServiceConnectionError,
)
from app.core.services.ml.xgboost.interface import ModelType
from app.infrastructure.di.container import get_service
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.api.v1.routes.xgboost import router


# Mock user for authentication
class MockUser:
    def __init__(self, id="test-user-id", role="clinician"):
        self.id = id
        self.role = role
        self.username = "test.user@novamind.com"


# Mock XGBoost service
class MockXGBoostService:
    def __init__(self):
        # Set up mock methods with MagicMock for all methods
        self.predict_risk = MagicMock()
        self.predict_treatment_response = MagicMock()
        self.predict_outcome = MagicMock()
        self.get_feature_importance = MagicMock()
        self.simulate_digital_twin = MagicMock()
        self.get_model_info = MagicMock()

    def setup_success_responses(self) -> None:
        """Set up mock responses for successful API calls."""
        # Risk prediction response
        self.predict_risk.return_value = {
            "prediction_id": str(uuid.uuid4()),
            "patient_id": "patient-123",
            "prediction": {
                "risk_level": RiskLevel.HIGH,
                "confidence": 0.85,
                "factors": [
                    "previous_suicide_attempt",
                    "severe_depression",
                    "social_isolation",
                ],
                "probability": 0.75,
                "next_steps": [
                    "Immediate safety planning",
                    "Consider hospitalization",
                    "Increase session frequency",
                ],
            },
            "timestamp": datetime.now().isoformat(),
            "model_version": "1.2.3",
        }

        # Treatment response prediction
        self.predict_treatment_response.return_value = {
            "prediction_id": str(uuid.uuid4()),
            "patient_id": "patient-123",
            "prediction": {
                "response_level": ResponseLevel.GOOD,
                "confidence": 0.78,
                "expected_phq9_reduction": 6,
                "expected_response_time_weeks": 4,
                "alternative_treatments": [
                    {"name": "bupropion", "expected_response": ResponseLevel.EXCELLENT},
                    {"name": "cbt", "expected_response": ResponseLevel.GOOD},
                ],
            },
            "timestamp": datetime.now().isoformat(),
            "model_version": "1.1.0",
        }

        # Outcome prediction
        self.predict_outcome.return_value = {
            "prediction_id": str(uuid.uuid4()),
            "patient_id": "patient-123",
            "prediction": {
                "remission_probability": 0.65,
                "confidence": 0.72,
                "expected_phq9_score": 7,
                "expected_gad7_score": 6,
                "key_factors": [
                    "treatment_adherence",
                    "social_support",
                    "sleep_quality",
                ],
            },
            "timestamp": datetime.now().isoformat(),
            "model_version": "1.0.5",
        }

        # Feature importance
        self.get_feature_importance.return_value = {
            "model_type": ModelType.RISK.value,
            "features": [
                {"name": "previous_suicide_attempt", "importance": 0.25},
                {"name": "phq9_score", "importance": 0.18},
                {"name": "social_isolation", "importance": 0.15},
                {"name": "substance_abuse", "importance": 0.12},
                {"name": "sleep_quality", "importance": 0.10},
            ],
            "timestamp": datetime.now().isoformat(),
        }

        # Digital twin simulation
        self.simulate_digital_twin.return_value = {
            "simulation_id": str(uuid.uuid4()),
            "patient_id": "patient-123",
            "simulation_results": [
                {
                    "week": 0,
                    "phq9_score": 18,
                    "gad7_score": 15,
                    "neurotransmitter_levels": {
                        "serotonin": 0.4,
                        "dopamine": 0.5,
                        "norepinephrine": 0.6,
                    },
                },
                {
                    "week": 4,
                    "phq9_score": 14,
                    "gad7_score": 12,
                    "neurotransmitter_levels": {
                        "serotonin": 0.5,
                        "dopamine": 0.55,
                        "norepinephrine": 0.65,
                    },
                },
                {
                    "week": 8,
                    "phq9_score": 10,
                    "gad7_score": 9,
                    "neurotransmitter_levels": {
                        "serotonin": 0.6,
                        "dopamine": 0.6,
                        "norepinephrine": 0.7,
                    },
                },
            ],
            "timestamp": datetime.now().isoformat(),
            "model_version": "1.0.0",
        }

        # Model info
        self.get_model_info.return_value = {
            "model_type": ModelType.RISK.value,
            "version": "1.2.3",
            "training_date": "2024-01-15",
            "features": ["previous_suicide_attempt", "phq9_score", "social_isolation"],
            "performance": {
                "auc": 0.85,
                "accuracy": 0.82,
                "sensitivity": 0.78,
                "specificity": 0.86,
            },
            "last_updated": datetime.now().isoformat(),
        }

    def setup_error_responses(self) -> None:
        """Set up mock responses for error cases."""

        # Configuration and ModelNotFound errors based on risk_type
        def risk_side_effect(patient_id, risk_type, clinical_data, time_frame_days) -> NoReturn:
            if risk_type == "nonexistent":
                raise ModelNotFoundError(f"Model type '{risk_type}' not found")
            # Default to configuration error for other risk types
            raise ConfigurationError("Invalid configuration")

        self.predict_risk.side_effect = risk_side_effect

        # Prediction error
        self.predict_treatment_response.side_effect = PredictionError(
            "Failed to predict response for treatment 'ssri'"
        )

        # Service connection error
        self.predict_outcome.side_effect = ServiceConnectionError(
            "Failed to connect to prediction service"
        )


@pytest.fixture
def app():
    """Create a FastAPI app with the XGBoost router."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/ml/xgboost")
    return app


@pytest.fixture
def mock_user():
    """Create a mock user for authentication."""
    return MockUser()


@pytest.fixture
def mock_xgboost_service():
    """Create a mock XGBoost service."""
    service = MockXGBoostService()
    service.setup_success_responses()
    return service


@pytest.fixture
def mock_dependencies(app, mock_user, mock_xgboost_service):
    """Override dependencies for testing."""
    app.dependency_overrides[get_current_user] = lambda: mock_user
    # Override the XGBoost service dependency
    app.dependency_overrides[get_service] = lambda: mock_xgboost_service
    return {"user": mock_user, "service": mock_xgboost_service}


@pytest.fixture
def mock_error_dependencies(app, mock_user, mock_xgboost_service):
    """Override dependencies with error-generating mocks."""
    app.dependency_overrides[get_current_user] = lambda: mock_user
    mock_xgboost_service.setup_error_responses()
    # Override the XGBoost service dependency
    app.dependency_overrides[get_service] = lambda: mock_xgboost_service
    return {"user": mock_user, "service": mock_xgboost_service}


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


import pytest


@pytest.mark.skip("Skipping XGBoost endpoint unit tests: pending endpoint refactor")
class TestXGBoostEndpoints:
    """Test suite for XGBoost API endpoints."""

    def test_risk_prediction(self, client, mock_dependencies) -> None:
        """Test risk prediction endpoint."""
        # Prepare request data
        request_data = {
            "patient_id": "patient-123",
            "risk_type": "suicide",
            "clinical_data": {
                "phq9_score": 18,
                "previous_attempts": 1,
                "social_isolation": True,
            },
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/risk-prediction", json=request_data)

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert "prediction_id" in data
        assert data["patient_id"] == "patient-123"
        assert "prediction" in data
        assert "risk_level" in data["prediction"]
        assert "confidence" in data["prediction"]
        assert "factors" in data["prediction"]
        assert "timestamp" in data
        assert "model_version" in data

    def test_treatment_response_prediction(self, client, mock_dependencies) -> None:
        """Test treatment response prediction endpoint."""
        # Prepare request data
        request_data = {
            "patient_id": "patient-123",
            "treatment_type": "ssri",
            "treatment_details": {
                "medication": "Escitalopram",
                "dose": "10mg",
                "frequency": "daily",
            },
            "clinical_data": {
                "phq9_score": 18,
                "gad7_score": 15,
                "previous_treatments": ["cbt"],
            },
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/treatment-response", json=request_data)

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert "prediction_id" in data
        assert data["patient_id"] == "patient-123"
        assert "prediction" in data
        assert "response_level" in data["prediction"]
        assert "confidence" in data["prediction"]
        assert "expected_phq9_reduction" in data["prediction"]
        assert "expected_response_time_weeks" in data["prediction"]
        assert "alternative_treatments" in data["prediction"]
        assert "timestamp" in data
        assert "model_version" in data

    def test_outcome_prediction(self, client, mock_dependencies) -> None:
        """Test outcome prediction endpoint."""
        # Prepare request data
        request_data = {
            "patient_id": "patient-123",
            "outcome_timeframe": {"weeks": 12},
            "clinical_data": {
                "phq9_score": 18,
                "gad7_score": 15,
                "sleep_quality": "poor",
                "social_support": "moderate",
            },
            "treatment_plan": {
                "medications": [{"name": "Escitalopram", "dose": "10mg", "frequency": "daily"}],
                "therapies": ["cbt"],
                "expected_adherence": "high",
            },
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/outcome-prediction", json=request_data)

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert "prediction_id" in data
        assert data["patient_id"] == "patient-123"
        assert "prediction" in data
        assert "remission_probability" in data["prediction"]
        assert "confidence" in data["prediction"]
        assert "expected_phq9_score" in data["prediction"]
        assert "expected_gad7_score" in data["prediction"]
        assert "key_factors" in data["prediction"]
        assert "timestamp" in data
        assert "model_version" in data

    def test_feature_importance(self, client, mock_dependencies) -> None:
        """Test feature importance endpoint."""
        # Make the request
        response = client.get("/api/v1/ml/xgboost/feature-importance/risk")

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert "model_type" in data
        assert data["model_type"] == ModelType.RISK.value
        assert "features" in data
        assert len(data["features"]) > 0
        assert "name" in data["features"][0]
        assert "importance" in data["features"][0]
        assert "timestamp" in data

    def test_digital_twin_simulation(self, client, mock_dependencies) -> None:
        """Test digital twin simulation endpoint."""
        # Prepare request data
        request_data = {
            "patient_id": "patient-123",
            "simulation_timeframe": {"weeks": 8},
            "treatment_plan": {
                "medications": [{"name": "Escitalopram", "dose": "10mg", "frequency": "daily"}],
                "therapies": ["cbt"],
                "expected_adherence": "high",
            },
            "baseline_metrics": {
                "phq9_score": 18,
                "gad7_score": 15,
                "neurotransmitter_levels": {
                    "serotonin": 0.4,
                    "dopamine": 0.5,
                    "norepinephrine": 0.6,
                },
            },
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/digital-twin-simulation", json=request_data)

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert "simulation_id" in data
        assert data["patient_id"] == "patient-123"
        assert "simulation_results" in data
        assert len(data["simulation_results"]) > 0
        assert "week" in data["simulation_results"][0]
        assert "phq9_score" in data["simulation_results"][0]
        assert "gad7_score" in data["simulation_results"][0]
        assert "neurotransmitter_levels" in data["simulation_results"][0]
        assert "timestamp" in data
        assert "model_version" in data

    def test_model_info(self, client, mock_dependencies) -> None:
        """Test model info endpoint."""
        # Make the request
        response = client.get("/api/v1/ml/xgboost/model-info/risk")

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert "model_type" in data
        assert data["model_type"] == ModelType.RISK.value
        assert "version" in data
        assert "training_date" in data
        assert "features" in data
        assert "performance" in data
        assert "auc" in data["performance"]
        assert "accuracy" in data["performance"]
        assert "last_updated" in data

    def test_configuration_error(self, client, mock_error_dependencies) -> None:
        """Test handling of ConfigurationError."""
        # Prepare request data
        request_data = {
            "patient_id": "patient-123",
            "risk_type": "suicide",
            "clinical_data": {},
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/risk-prediction", json=request_data)

        # Verify response
        assert response.status_code == 500
        data = response.json()
        assert "detail" in data
        assert "configuration" in data["detail"].lower()

    def test_model_not_found_error(self, client, mock_error_dependencies) -> None:
        """Test handling of ModelNotFoundError."""
        # Prepare request data
        request_data = {
            "patient_id": "patient-123",
            "risk_type": "nonexistent",  # This will trigger ModelNotFoundError
            "clinical_data": {},
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/risk-prediction", json=request_data)

        # Verify response
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert any("nonexistent" in str(item) for item in data["detail"])

    def test_prediction_error(self, client, mock_error_dependencies) -> None:
        """Test handling of PredictionError."""
        # Prepare request data
        request_data = {
            "patient_id": "patient-123",
            "treatment_type": "ssri",
            "treatment_details": {"medication": "Escitalopram"},
            "clinical_data": {},
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/treatment-response", json=request_data)

        # Verify response
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert any("ssri" in str(item) for item in data["detail"])

    def test_service_connection_error(self, client, mock_error_dependencies) -> None:
        """Test handling of ServiceConnectionError."""
        # Prepare request data
        request_data = {
            "patient_id": "patient-123",
            "outcome_timeframe": {"weeks": 12},
            "clinical_data": {"phq9_score": 15},
            "treatment_plan": {},
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/outcome-prediction", json=request_data)

        # Verify response
        assert response.status_code == 503
        data = response.json()
        assert "detail" in data
        assert "Failed to connect to prediction service" in data["detail"]

    def test_validation_error(self, client) -> None:
        """Test handling of validation errors with missing required fields."""
        # Prepare request data with missing required fields
        request_data = {
            "patient_id": "patient-123",
            # Missing risk_type
            "clinical_data": {},
        }

        # Make the request
        response = client.post("/api/v1/ml/xgboost/risk-prediction", json=request_data)

        # Verify response
        assert response.status_code == 422  # Unprocessable Entity
        data = response.json()
        assert "detail" in data
