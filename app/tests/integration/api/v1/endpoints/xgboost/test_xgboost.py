"""
Integration tests for XGBoost API endpoints.

These tests verify that the XGBoost API endpoints correctly validate input,
handle authentication, and pass data to and from the service layer.
"""

from collections.abc import AsyncGenerator
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Tuple
from unittest.mock import AsyncMock, patch
import uuid
import httpx
import logging
import asyncio
import pytest
import pytest_asyncio
from app.tests.utils.asyncio_helpers import run_with_timeout, run_with_timeout_asyncio
from fastapi import FastAPI, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient, ASGITransport
from app.core.config import Settings
from app.core.domain.entities.user import User, UserRole, UserStatus
from app.core.services.ml.xgboost.exceptions import (
    DataPrivacyError,
    ModelNotFoundError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from app.core.interfaces.services.ml.xgboost import XGBoostInterface
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_dependency
from app.infrastructure.security.audit.middleware import AuditLogMiddleware
from app.tests.utils.test_audit_utils import disable_audit_middleware, replace_middleware_with_mock
from app.app_factory import create_application
from app.presentation.api.dependencies.auth import (
    verify_provider_access,
    get_current_user,
)
from app.presentation.api.v1.routes.xgboost import get_xgboost_service
from app.tests.integration.utils.test_authentication import create_test_headers_for_role
from app.tests.integration.utils.test_config import setup_test_environment

# Initialize logger
logger = logging.getLogger(__name__)

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio

# Create a concrete implementation of XGBoostInterface for tests
class MockXGBoostService:
    """Mock XGBoost service with AsyncMock methods for testing."""
    
    def __init__(self):
        self._initialized = True  # Pre-initialize for tests
        self.predict_risk_mock = AsyncMock()
        self.predict_treatment_response_mock = AsyncMock()
        self.predict_outcome_mock = AsyncMock()
        self.get_feature_importance_mock = AsyncMock()
        self.integrate_with_digital_twin_mock = AsyncMock()
        self.get_model_info_mock = AsyncMock()
        self.post_model_info_mock = AsyncMock()
        self.get_available_models_mock = AsyncMock()
        
    async def predict(self, patient_id, features, model_type, **kwargs):
        """Generic prediction method required by MLServiceInterface."""
        if "risk" in model_type.lower():
            return await self.predict_risk(patient_id, model_type, features)
        elif "treatment" in model_type.lower():
            return await self.predict_treatment_response(patient_id, model_type, {}, features)
        elif "outcome" in model_type.lower():
            return await self.predict_outcome(patient_id, features, kwargs.get("timeframe_days", 0), clinical_data=kwargs.get("clinical_data", {}), treatment_plan=kwargs.get("treatment_plan", {}))
        raise ValueError(f"Unknown model type: {model_type}")
    
    async def predict_risk(self, patient_id, risk_type, features):
        """Mock risk prediction."""
        return await self.predict_risk_mock(patient_id, risk_type, features)
    
    async def predict_treatment_response(self, patient_id, treatment_id, treatment_plan, features):
        """Mock treatment response prediction."""
        return await self.predict_treatment_response_mock(patient_id, treatment_id, treatment_plan, features)
    
    async def predict_outcome(self, patient_id, features, timeframe_days, clinical_data=None, treatment_plan=None):
        """Mock outcome prediction."""
        return await self.predict_outcome_mock(patient_id, features, timeframe_days, clinical_data=clinical_data, treatment_plan=treatment_plan)
    
    async def get_feature_importance(self, model_id, model_type=None):
        """Mock feature importance retrieval."""
        return await self.get_feature_importance_mock(model_id, model_type)
    
    async def integrate_with_digital_twin(self, patient_id, digital_twin_id, features):
        """Mock digital twin integration."""
        return await self.integrate_with_digital_twin_mock(patient_id, digital_twin_id, features)
    
    async def get_model_info(self, model_id=None, model_type=None):
        """Mock model info retrieval."""
        return await self.get_model_info_mock(model_id, model_type)
    
    async def post_model_info(self, model_info):
        """Mock saving model information."""
        return await self.post_model_info_mock(model_info)
    
    async def get_available_models(self, filter_criteria=None):
        """Mock available models retrieval."""
        return await self.get_available_models_mock(filter_criteria)


@pytest.fixture
def mock_xgboost_service():
    """Create an instance of the mock XGBoost service."""
    return MockXGBoostService()


@pytest_asyncio.fixture
async def db_session():
    """Create a database session for tests."""
    # Use in-memory SQLite for testing
    settings = Settings(
        ENVIRONMENT="test",
        TESTING=True,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
    )
    
    # Setup test database and session
    session = await setup_test_environment(settings)
    
    yield session
    
    # Clean up
    await session.close()


@pytest_asyncio.fixture
async def xgboost_test_client(mock_xgboost_service, db_session) -> AsyncGenerator[Tuple[FastAPI, AsyncClient], None]:
    """Create an HTTP client for testing the XGBoost endpoints."""
    # Create application with test settings
    settings = Settings(
        ENVIRONMENT="test",
        TESTING=True,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        API_V1_STR="/api/v1",
        JWT_SECRET_KEY="test_secret_key_for_testing_only",
    )
    
    # Override dependencies for testing
    app = create_application(settings_override=settings, include_test_routers=True)
    
    # Explicitly disable audit middleware
    disable_audit_middleware(app)
    
    # Mock the XGBoost service dependency
    app.dependency_overrides[get_xgboost_service] = lambda: mock_xgboost_service
    
    # Mock authentication for tests
    async def mock_current_user() -> User:
        """Return a mock user for testing."""
        return User(
            id=str(uuid.uuid4()),
            username="test_user",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.PROVIDER,
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
    
    # Override the auth dependency
    app.dependency_overrides[get_current_user] = mock_current_user
    
    # Also override provider access verification
    app.dependency_overrides[verify_provider_access] = lambda: True
    
    # Create test client
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Content-Type": "application/json"},
    ) as client:
        yield app, client
    
    # Clean up
    app.dependency_overrides.clear()


@pytest.fixture
def risk_prediction_request_data():
    """Generate mock data for risk prediction requests."""
    return {
        "patient_id": str(uuid.uuid4()),
        "risk_type": "suicide",
        "features": {
            "age": 35,
            "gender": "female",
            "diagnosis": "major_depression",
            "previous_attempts": 1,
            "substance_abuse_history": True,
            "family_history": True,
            "recent_life_events": ["divorce", "job_loss"],
            "symptom_severity": 8,
        },
    }


@pytest.fixture
def treatment_response_request_data():
    """Generate mock data for treatment response prediction requests."""
    return {
        "patient_id": str(uuid.uuid4()),
        "treatment_id": "cbt_therapy",
        "treatment_plan": {
            "frequency": "weekly",
            "duration_weeks": 12,
            "intensity": "standard",
        },
        "features": {
            "age": 42,
            "gender": "male",
            "diagnosis": "anxiety",
            "symptom_duration_months": 6,
            "previous_treatments": ["medication", "counseling"],
            "comorbidities": ["insomnia"],
            "symptom_severity": 7,
        },
    }


@pytest.fixture
def outcome_prediction_request_data():
    """Generate mock data for outcome prediction requests."""
    return {
        "patient_id": str(uuid.uuid4()),
        "timeframe_days": 90,
        "features": {
            "age": 29,
            "gender": "non_binary",
            "diagnosis": "bipolar",
            "symptom_duration_years": 3,
            "medication_adherence": 0.85,
            "therapy_engagement": 0.7,
            "social_support": 0.6,
            "lifestyle_factors": {
                "exercise_frequency": "moderate",
                "sleep_quality": "poor",
                "substance_use": "occasional",
            },
        },
        "clinical_data": {
            "lab_results": {
                "thyroid_function": "normal",
                "vitamin_d": "low",
            },
            "vital_signs": {
                "blood_pressure": "120/80",
                "heart_rate": 72,
            },
        },
        "treatment_plan": {
            "medications": [
                {"name": "lithium", "dosage": "900mg", "frequency": "daily"},
                {"name": "quetiapine", "dosage": "50mg", "frequency": "nightly"},
            ],
            "therapy": {
                "type": "cognitive_behavioral_therapy",
                "frequency": "weekly",
            },
            "lifestyle_modifications": [
                "improved_sleep_hygiene",
                "regular_exercise",
                "stress_reduction_techniques",
            ],
        },
    }

# Tests for risk prediction endpoints
async def test_predict_risk(xgboost_test_client, risk_prediction_request_data):
    """Test the risk prediction endpoint."""
    app, client = xgboost_test_client
    mock_service = app.dependency_overrides[get_xgboost_service]()
    
    # Set up the mock response
    expected_response = {
        "risk_score": 0.72,
        "risk_level": "high",
        "confidence": 0.85,
        "factors": [
            {"name": "previous_attempts", "importance": 0.35},
            {"name": "symptom_severity", "importance": 0.25},
            {"name": "recent_life_events", "importance": 0.20},
            {"name": "substance_abuse_history", "importance": 0.15},
            {"name": "family_history", "importance": 0.05},
        ],
        "recommended_actions": [
            {"action": "immediate_assessment", "urgency": "high"},
            {"action": "safety_planning", "urgency": "high"},
            {"action": "increase_therapy_frequency", "urgency": "medium"},
        ],
    }
    
    # Configure the mock to return our expected response
    mock_service.predict_risk_mock.return_value = expected_response
    
    # Make the request
    response = await client.post(
        f"{app.state.settings.API_V1_STR}/xgboost/predict/risk",
        json=risk_prediction_request_data,
    )
    
    # Check the response
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == expected_response
    
    # Verify the mock was called with correct arguments
    mock_service.predict_risk_mock.assert_called_once_with(
        risk_prediction_request_data["patient_id"],
        risk_prediction_request_data["risk_type"],
        risk_prediction_request_data["features"],
    )

# Add more tests for different scenarios and other endpoints
