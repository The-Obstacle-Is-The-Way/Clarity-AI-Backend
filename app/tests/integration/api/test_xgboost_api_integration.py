"""
Integration tests for XGBoost API endpoints.

These tests verify that the XGBoost API endpoints correctly validate input,
handle authentication, and pass data to and from the service layer.
"""

import pytest
import pytest_asyncio
import inspect
import uuid
import json
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import AsyncClient
from fastapi import status
from datetime import datetime, timezone
import logging

from app.presentation.api.schemas.xgboost import (
    RiskPredictionRequest,
    TreatmentResponseRequest,
    OutcomePredictionRequest,
)
from app.core.services.ml.xgboost.interface import XGBoostInterface
from app.core.services.ml.xgboost.exceptions import (
    ValidationError,
    DataPrivacyError,
    ResourceNotFoundError,
    ModelNotFoundError,
    ServiceUnavailableError
)

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio

from typing import Generator, Dict, Any, AsyncGenerator
from app.main import create_application
from fastapi import FastAPI
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_dependency
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.routes.xgboost import get_xgboost_service, validate_permissions
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware

# Create a concrete implementation of XGBoostInterface for tests
class MockXGBoostService(XGBoostInterface):
    def __init__(self):
        super().__init__()
        self._initialized = True  # Pre-initialize for tests
        self.predict_risk_mock = AsyncMock()
        self.predict_treatment_response_mock = AsyncMock()
        self.predict_outcome_mock = AsyncMock()
        self.get_feature_importance_mock = AsyncMock()
        self.integrate_with_digital_twin_mock = AsyncMock()
        self.get_model_info_mock = AsyncMock()
        self.post_model_info_mock = AsyncMock()
        self.get_available_models_mock = AsyncMock()
        
    # Implementation of abstract methods from XGBoostInterface
    def initialize(self, config: Dict[str, Any]):
        self._initialized = True
        return None
        
    def register_observer(self, event_type, observer):
        return None
        
    def unregister_observer(self, event_type, observer):
        return None
        
    def get_available_models(self):
        return []
        
    def is_initialized(self):
        return self._initialized
        
    # Mock implementations for the service methods
    async def predict_risk(self, patient_id: str, risk_type: str, clinical_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        return await self.predict_risk_mock(patient_id, risk_type, clinical_data, **kwargs)
        
    async def predict_treatment_response(self, patient_id: str, treatment_type: str, treatment_details: Dict[str, Any], clinical_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        return await self.predict_treatment_response_mock(patient_id, treatment_type, clinical_data, **kwargs)
        
    async def predict_outcome(self, patient_id: str, outcome_timeframe: Dict[str, int], clinical_data: Dict[str, Any], treatment_plan: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        return await self.predict_outcome_mock(patient_id, outcome_timeframe, clinical_data, treatment_plan, **kwargs)
        
    async def get_feature_importance(self, patient_id: str, model_type: str, prediction_id: str) -> Dict[str, Any]:
        return await self.get_feature_importance_mock(patient_id, model_type, prediction_id)
        
    async def integrate_with_digital_twin(self, patient_id: str, profile_id: str, prediction_id: str) -> Dict[str, Any]:
        return await self.integrate_with_digital_twin_mock(patient_id, profile_id, prediction_id)
        
    async def get_model_info(self, model_type: str) -> Dict[str, Any]:
        return await self.get_model_info_mock(model_type)
        
    async def post_model_info(self, model_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.post_model_info_mock(model_data)

@pytest.fixture
def test_app(mock_xgboost_service, db_session) -> FastAPI:
    """Create a FastAPI application instance with xgboost mocks for testing."""
    # Define the override function for database
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    # Define the override function for XGBoost service
    def override_get_xgboost_service() -> XGBoostInterface:
        return mock_xgboost_service
    
    # --- Auth Overrides (Removed/Commented Out) --- 
    # Import the actual dependencies we need to override
    # from app.presentation.api.dependencies.auth import get_current_user, verify_provider_access
    
    # Override get_current_user to return a default mock user
    # async def override_get_current_user():
    #     return {
    #         "sub": "auth0|default_test_user", 
    #         "name": "Test User", 
    #         "email": "test@example.com",
    #         "role": "provider",
    #         "permissions": ["predict_risk", "predict_treatment", "predict_outcome"]
    #     }

    # Define an override for verification that always passes
    # def override_verify_provider_access(): 
    #     return {
    #         "id": "provider-test-id",
    #         "role": "provider",
    #         "permissions": ["predict_risk", "predict_treatment", "predict_outcome"]
    #     }
        
    # Override validate_permissions to prevent 403 errors
    # def override_validate_permissions():
    #     return None
    # --- End Auth Overrides ---
        
    # Create app, WITH the AuthenticationMiddleware
    from app.main import create_application # Ensure create_application is imported
    app = create_application()

    # Apply necessary dependency overrides AFTER app creation
    app.dependency_overrides[get_db_dependency] = override_get_db
    app.dependency_overrides[get_xgboost_service] = override_get_xgboost_service
    # Removed auth overrides
    # app.dependency_overrides[get_current_user] = override_get_current_user
    # app.dependency_overrides[verify_provider_access] = override_verify_provider_access
    # app.dependency_overrides[validate_permissions] = override_validate_permissions
    
    yield app # Use yield for proper setup/teardown

    # Clear overrides after test
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Create an AsyncClient instance for testing."""
    async with AsyncClient(app=test_app, base_url="http://test") as client:
        yield client

@pytest.fixture(scope="session")
def mock_xgboost_service() -> MockXGBoostService:
    """Create a mock XGBoost service implementation."""
    return MockXGBoostService()

# These header fixtures now depend on the actual token generation from conftest.py
# (Assuming they are defined there and correctly imported/available)
# If not, they need to be adjusted to call the token generation fixtures.
@pytest.fixture
def psychiatrist_auth_headers(get_valid_provider_auth_headers: Dict[str, str]) -> Dict[str, str]:
    """Use valid provider headers."""
    return get_valid_provider_auth_headers

@pytest.fixture
def provider_auth_headers(get_valid_provider_auth_headers: Dict[str, str]) -> Dict[str, str]:
    """Use valid provider headers."""
    return get_valid_provider_auth_headers

@pytest.fixture
def patient_auth_headers(get_valid_auth_headers: Dict[str, str]) -> Dict[str, str]:
    """Use valid patient headers."""
    return get_valid_auth_headers


@pytest.fixture
def valid_risk_prediction_data() -> Dict[str, Any]:
    """Valid data for risk prediction request."""
    return {
        "patient_id": "test-patient-123",
        "risk_type": "relapse",
        "clinical_data": {
            "phq9_score": 12,
            "gad7_score": 9,
            "symptom_duration_weeks": 8,
            "previous_episodes": 2,
            "medication_adherence": 0.8
        },
        "patient_data": {
            "age": 35,
            "gender": "female",
            "education_level": "college"
        },
        "time_frame_days": 90,  # Required by schema
        "confidence_threshold": 0.7
    }

@pytest.fixture
def valid_treatment_response_data() -> Dict[str, Any]:
    """Valid data for treatment response prediction request."""
    return {
        "patient_id": "test-patient-123",
        "treatment_type": "medication",
        "treatment_details": {
            "medication_class": "SSRI",
            "dosage": "20mg",
            "frequency": "daily",
            "duration_weeks": 12
        },
        "clinical_data": {
            "phq9_score": 15,
            "gad7_score": 11,
            "symptom_duration_weeks": 12,
            "previous_episodes": 1
        },
        "genetic_data": ["CYP2D6*1/*2", "CYP2C19*1/*1"],
        "treatment_history": [
            {
                "medication": "Sertraline",
                "dosage": "50mg",
                "duration_weeks": 8,
                "response": "partial",
                "side_effects": ["nausea", "insomnia"]
            }
        ]
    }

@pytest.fixture
def valid_outcome_prediction_data() -> Dict[str, Any]:
    """Valid data for outcome prediction request."""
    return {
        "patient_id": "test-patient-123",
        "outcome_timeframe": {"months": 6},
        "clinical_data": {
            "phq9_score": 10,
            "gad7_score": 7,
            "symptom_duration_weeks": 10,
            "previous_episodes": 1,
            "medication_adherence": 0.9,
            "therapy_sessions_attended": 5
        },
        "treatment_plan": {
            "medication": {
                "name": "Escitalopram",
                "dosage": "10mg",
                "frequency": "daily"
            },
            "therapy": {
                "type": "CBT",
                "frequency": "weekly",
                "duration_weeks": 12
            }
        },
        "socioeconomic_factors": {
            "employment_status": "employed",
            "social_support_level": "moderate"
        }
    }


@pytest.mark.asyncio
class TestXGBoostAPIIntegration:
    """Test suite for XGBoost API integration focusing on authentication and validation."""

    async def test_predict_risk_success(
        self,
        async_client: AsyncClient,
        mock_xgboost_service: MockXGBoostService,
        valid_risk_prediction_data: Dict[str, Any],
        provider_auth_headers: Dict[str, str] # Use provider headers
    ):
        """Test successful risk prediction with valid data and authentication."""
        mock_xgboost_service.predict_risk_mock.return_value = {
            "prediction_id": str(uuid.uuid4()),
            "patient_id": valid_risk_prediction_data["patient_id"],
            "risk_score": 0.65,
            "risk_level": "moderate",
            "confidence": 0.8,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        response = await async_client.post(
            "/api/v1/xgboost/predict/risk",
            json=valid_risk_prediction_data,
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
        data = response.json()
        assert data["patient_id"] == valid_risk_prediction_data["patient_id"]
        assert "prediction_id" in data
        assert "risk_score" in data
        mock_xgboost_service.predict_risk_mock.assert_awaited_once()

    async def test_predict_risk_validation_error(
        self,
        async_client: AsyncClient,
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str] # Use provider headers
    ):
        """Test risk prediction with invalid input data (missing field)."""
        invalid_data = {
            "patient_id": "test-patient-123",
            # "risk_type": "relapse", # Missing risk_type
            "clinical_data": {"phq9_score": 12}
        }

        response = await async_client.post(
            "/api/v1/xgboost/predict/risk",
            json=invalid_data,
            headers=provider_auth_headers # Pass headers
        )

        # Expect 422 Unprocessable Entity due to FastAPI validation
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY, f"Response: {response.text}"
        # Ensure the service method was NOT called
        mock_xgboost_service.predict_risk_mock.assert_not_awaited()

    async def test_predict_risk_phi_detection(
        self,
        async_client: AsyncClient,
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str] # Use provider headers
    ):
        """Test risk prediction request blocked due to potential PHI in free-text fields (if applicable)."""
        # Assuming some field like 'notes' could contain PHI
        phi_data = {
            "patient_id": "test-patient-phi",
            "risk_type": "suicide",
            "clinical_data": {
                "phq9_score": 22,
                "gad7_score": 18,
                "notes": "Patient John Doe mentioned feeling hopeless."
            },
            "patient_data": { "age": 40 },
            "time_frame_days": 30
        }

        # Mock the service to raise DataPrivacyError if called
        mock_xgboost_service.predict_risk_mock.side_effect = DataPrivacyError("Simulated PHI detected")

        response = await async_client.post(
            "/api/v1/xgboost/predict/risk",
            json=phi_data,
            headers=provider_auth_headers # Pass headers
        )

        # Assuming PHI detection happens *before* or *within* the service call
        # If PHI middleware blocks first, it might be 400 or 422 depending on implementation.
        # If service blocks, it should map the DataPrivacyError to 400.
        assert response.status_code == status.HTTP_400_BAD_REQUEST, f"Response: {response.text}"
        data = response.json()
        assert "privacy violation" in data.get("message", "").lower() or \
               "phi detected" in data.get("message", "").lower()
        # Reset side effect for other tests
        mock_xgboost_service.predict_risk_mock.side_effect = None


    async def test_predict_risk_unauthorized(
        self,
        async_client: AsyncClient,
        mock_xgboost_service: MockXGBoostService,
        valid_risk_prediction_data: Dict[str, Any],
        patient_auth_headers: Dict[str, str] # Use patient headers (insufficient permissions)
    ):
        """Test risk prediction attempt with insufficient permissions (e.g., patient role)."""

        response = await async_client.post(
            "/api/v1/xgboost/predict/risk",
            json=valid_risk_prediction_data,
            headers=patient_auth_headers # Pass patient headers
        )

        # Expect 403 Forbidden due to role/permission check
        assert response.status_code == status.HTTP_403_FORBIDDEN, f"Response: {response.text}"
        # Ensure the service method was NOT called
        mock_xgboost_service.predict_risk_mock.assert_not_awaited()


    async def test_predict_treatment_response_success(
        self,
        async_client: AsyncClient, # Use async_client
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str], # Renamed fixture, use provider
        valid_treatment_response_data: Dict[str, Any]
    ):
        """Test successful treatment response prediction."""
        mock_xgboost_service.predict_treatment_response_mock.return_value = {
            "prediction_id": str(uuid.uuid4()),
            "patient_id": valid_treatment_response_data["patient_id"],
            "treatment_type": valid_treatment_response_data["treatment_type"],
            "response_probability": 0.75,
            "predicted_response": "likely_responder",
            "confidence": 0.85,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        response = await async_client.post( # Use await with async_client
            "/api/v1/xgboost/predict/treatment-response",
            json=valid_treatment_response_data,
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
        data = response.json()
        assert data["patient_id"] == valid_treatment_response_data["patient_id"]
        assert "prediction_id" in data
        assert "response_probability" in data
        mock_xgboost_service.predict_treatment_response_mock.assert_awaited_once()

    async def test_predict_outcome_success(
        self,
        async_client: AsyncClient, # Use async_client
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str],
        valid_outcome_prediction_data: Dict[str, Any]
    ):
        """Test successful outcome prediction."""
        mock_xgboost_service.predict_outcome_mock.return_value = {
            "prediction_id": str(uuid.uuid4()),
            "patient_id": valid_outcome_prediction_data["patient_id"],
            "outcome_probabilities": {
                "remission": 0.6,
                "partial_response": 0.3,
                "no_response": 0.1
            },
            "predicted_outcome": "remission",
            "confidence": 0.78,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        response = await async_client.post( # Use await with async_client
            "/api/v1/xgboost/predict/outcome",
            json=valid_outcome_prediction_data,
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
        data = response.json()
        assert data["patient_id"] == valid_outcome_prediction_data["patient_id"]
        assert "prediction_id" in data
        assert "predicted_outcome" in data
        mock_xgboost_service.predict_outcome_mock.assert_awaited_once()

    async def test_get_feature_importance_success(
        self,
        async_client: AsyncClient, # Use async_client
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str] # Renamed fixture, use provider
    ):
        """Test successful retrieval of feature importance."""
        patient_id = "patient-feat-imp-1"
        model_type = "risk_prediction"
        prediction_id = str(uuid.uuid4())

        mock_xgboost_service.get_feature_importance_mock.return_value = {
            "prediction_id": prediction_id,
            "model_type": model_type,
            "feature_importance": {
                "phq9_score": 0.35,
                "previous_episodes": 0.25,
                "medication_adherence": 0.15,
                "age": 0.10,
                "gad7_score": 0.08,
                "symptom_duration_weeks": 0.07
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        response = await async_client.get( # Use await with async_client
            f"/api/v1/xgboost/explain/{model_type}/{prediction_id}",
            params={"patient_id": patient_id}, # Pass patient_id as query param if needed
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
        data = response.json()
        assert data["prediction_id"] == prediction_id
        assert "feature_importance" in data
        mock_xgboost_service.get_feature_importance_mock.assert_awaited_once_with(
            patient_id=patient_id, model_type=model_type, prediction_id=prediction_id
        )

    async def test_get_feature_importance_not_found(
        self,
        async_client: AsyncClient, # Use async_client
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str] # Renamed fixture, use provider
    ):
        """Test retrieval of feature importance for a non-existent prediction."""
        patient_id = "patient-feat-imp-nf"
        model_type = "risk_prediction"
        prediction_id = "non-existent-prediction-id"

        mock_xgboost_service.get_feature_importance_mock.side_effect = ResourceNotFoundError("Prediction not found")

        response = await async_client.get( # Use await with async_client
            f"/api/v1/xgboost/explain/{model_type}/{prediction_id}",
            params={"patient_id": patient_id},
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND, f"Response: {response.text}"
        mock_xgboost_service.get_feature_importance_mock.assert_awaited_once_with(
            patient_id=patient_id, model_type=model_type, prediction_id=prediction_id
        )
        # Reset side effect
        mock_xgboost_service.get_feature_importance_mock.side_effect = None

    async def test_integrate_with_digital_twin_success(
        self,
        async_client: AsyncClient, # Use async_client
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str] # Renamed fixture, use provider
    ):
        """Test successful integration of a prediction with the digital twin."""
        patient_id = "patient-dt-int-1"
        profile_id = "digital-twin-profile-abc"
        prediction_id = str(uuid.uuid4())

        mock_xgboost_service.integrate_with_digital_twin_mock.return_value = {
            "integration_id": str(uuid.uuid4()),
            "profile_id": profile_id,
            "prediction_id": prediction_id,
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": "Prediction incorporated into digital twin profile."
        }

        integration_payload = {
            "patient_id": patient_id,
            "profile_id": profile_id
        }

        response = await async_client.post( # Use await with async_client
            f"/api/v1/xgboost/integrate/{prediction_id}",
            json=integration_payload,
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
        data = response.json()
        assert data["profile_id"] == profile_id
        assert data["prediction_id"] == prediction_id
        assert data["status"] == "success"
        mock_xgboost_service.integrate_with_digital_twin_mock.assert_awaited_once_with(
            patient_id=patient_id, profile_id=profile_id, prediction_id=prediction_id
        )

    async def test_get_model_info_success(
        self,
        async_client: AsyncClient, # Use async_client
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str] # Use provider headers for consistency
    ):
        """Test successful retrieval of model information."""
        model_type = "risk_prediction"

        mock_xgboost_service.get_model_info_mock.return_value = {
            "model_type": model_type,
            "version": "1.2.0",
            "description": "XGBoost model for predicting patient risk.",
            "trained_at": "2023-10-26T10:00:00Z",
            "performance_metrics": {
                "accuracy": 0.85,
                "precision": 0.88,
                "recall": 0.82,
                "f1_score": 0.85,
                "auc": 0.92
            },
            "features": [
                "phq9_score",
                "gad7_score",
                "symptom_duration_weeks",
                "previous_episodes",
                "medication_adherence",
                "age",
                "gender"
            ]
        }

        response = await async_client.get( # Use await with async_client
            f"/api/v1/xgboost/info/{model_type}",
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
        data = response.json()
        assert data["model_type"] == model_type
        assert "version" in data
        assert "performance_metrics" in data
        mock_xgboost_service.get_model_info_mock.assert_awaited_once_with(model_type=model_type)

    async def test_get_model_info_not_found(
        self,
        async_client: AsyncClient, # Use async_client
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str] # Use provider headers
    ):
        """Test retrieval of model info for a non-existent model type."""
        model_type = "non_existent_model"

        mock_xgboost_service.get_model_info_mock.side_effect = ModelNotFoundError(f"Model type '{model_type}' not found")

        response = await async_client.get( # Use await with async_client
            f"/api/v1/xgboost/info/{model_type}",
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND, f"Response: {response.text}"
        mock_xgboost_service.get_model_info_mock.assert_awaited_once_with(model_type=model_type)
        # Reset side effect
        mock_xgboost_service.get_model_info_mock.side_effect = None

    async def test_service_unavailable(
        self,
        async_client: AsyncClient, # Use async_client
        mock_xgboost_service: MockXGBoostService,
        provider_auth_headers: Dict[str, str], # Use provider headers
        valid_risk_prediction_data: Dict[str, Any]
    ):
        """Test API response when the XGBoost service is unavailable."""
        mock_xgboost_service.predict_risk_mock.side_effect = ServiceUnavailableError("XGBoost service is down")

        response = await async_client.post( # Use await with async_client
            "/api/v1/xgboost/predict/risk",
            json=valid_risk_prediction_data,
            headers=provider_auth_headers # Pass headers
        )

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE, f"Response: {response.text}"
        data = response.json()
        assert "service unavailable" in data.get("message", "").lower()
        mock_xgboost_service.predict_risk_mock.assert_awaited_once()
        # Reset side effect
        mock_xgboost_service.predict_risk_mock.side_effect = None

    async def test_predict_risk_no_auth(self, async_client: AsyncClient, valid_risk_prediction_data: Dict[str, Any]):
        """Test predict risk endpoint without authentication headers."""
        response = await async_client.post(
            "/api/v1/xgboost/predict/risk",
            json=valid_risk_prediction_data
            # No headers provided
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Response: {response.text}"

    async def test_get_model_info_no_auth(self, async_client: AsyncClient):
        """Test get model info endpoint without authentication headers."""
        response = await async_client.get("/api/v1/xgboost/info/risk_prediction")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Response: {response.text}"
