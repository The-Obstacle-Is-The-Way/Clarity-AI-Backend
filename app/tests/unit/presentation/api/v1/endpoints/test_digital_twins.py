"""
Unit tests for Digital Twin API endpoints.

Tests the API endpoints for Digital Twin functionality, including
the MentaLLaMA integration for clinical text processing.
"""
# Standard Library Imports
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4
import logging

# Initialize logger
logger = logging.getLogger(__name__)

# Third-Party Imports
from fastapi import FastAPI, status, HTTPException
from httpx import AsyncClient
import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout
import signal
import functools

# First-Party Imports (Organized)
# Assuming base exceptions are in core.exceptions.base_exceptions
from app.core.exceptions.base_exceptions import (
    ModelExecutionError,  # Changed from ModelInferenceError
    ResourceNotFoundError,
)
from app.domain.entities.user import User  # Added User import
from app.presentation.api.dependencies.auth import get_current_user, get_current_active_user  # Standard auth dependency
from app.presentation.api.dependencies.services import (
    get_digital_twin_service,
)
# Import digital_twin specific services
from app.presentation.api.v1.dependencies.digital_twin import get_digital_twin_service
from app.presentation.api.schemas.digital_twin import (
    # ClinicalTextAnalysisResponse, # Let's use the specific fixture name for clarity if needed
    PersonalizedInsightResponse, # Assuming this covers the /insights endpoint test case
)
from app.presentation.api.v1.routes.digital_twin import router as digital_twin_router

# Add imports for create_application and Settings
from app.app_factory import create_application
from app.core.config.settings import Settings as AppSettings # Use alias
from app.presentation.middleware.authentication import AuthenticationMiddleware

# Define UTC timezone
UTC = timedelta(0) # Simple UTC offset

# Test Constants
TEST_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjk5OTk5OTk5OTl9.N_8jTh-tkBrr7R3lxh9jgfY9H5hZLT7z87Mjzn8w7F4"

# Fixtures
@pytest.fixture
def mock_digital_twin_service():
    """Create a mock DigitalTwinIntegrationService."""
    # service = AsyncMock(spec=DigitalTwinIntegrationService) # Use spec if class is available
    service = AsyncMock() # Use basic AsyncMock if spec import is problematic

    # Mock top-level methods
    service.get_twin_for_user = AsyncMock()
    service.get_digital_twin_status = AsyncMock()
    service.generate_comprehensive_patient_insights = AsyncMock()
    service.analyze_clinical_text_mentallama = AsyncMock() # Assuming this method exists for the endpoint

    return service

@pytest.fixture
def mock_current_user():
    """Fixture for a mock User object."""
    from app.core.domain.entities.user import UserStatus
    return User(
        id=UUID("00000000-0000-0000-0000-000000000001"), 
        role="admin", 
        email="test@example.com",
        status=UserStatus.ACTIVE,  # Add active status
        roles=["admin"]  # Ensure roles is a list
    )

@pytest.fixture
def app(mock_digital_twin_service: AsyncMock, mock_current_user: User) -> FastAPI:
    """Override the app fixture to use a real FastAPI instance for these tests."""
    test_settings = AppSettings() # Create a default settings instance for tests
    app_instance = create_application(
        settings_override=test_settings, 
        skip_auth_middleware=True  # Skip authentication middleware completely
    )
    
    # Apply dependency overrides relevant for these unit tests
    app_instance.dependency_overrides[get_current_user] = lambda: mock_current_user
    app_instance.dependency_overrides[get_current_active_user] = lambda: mock_current_user
    
    # Override the specific digital_twin_service dependency from the correct module
    from app.presentation.api.v1.dependencies.digital_twin import get_digital_twin_service as dt_service_dep
    app_instance.dependency_overrides[dt_service_dep] = lambda: mock_digital_twin_service
    
    # Direct import and mounting of the digital_twin router for tests
    from app.presentation.api.v1.routes.digital_twin import router as digital_twin_router
    
    # Clear existing routes to avoid duplicates
    app_instance.router.routes = []
    
    # For debugging - print all routes
    print("\nDebug: Available routes and patterns before mounting:")
    print([f"{route.path} ({route.name})" for route in app_instance.routes])
    
    # Include digital twin router directly with the same prefix as in api_router.py
    app_instance.include_router(digital_twin_router, prefix="/api/v1/digital-twins")
    
    # For debugging - print all routes after mounting
    print("\nDebug: Available routes and patterns after mounting digital-twins:")
    print([f"{route.path} ({route.name})" for route in app_instance.routes])

    return app_instance

@pytest.fixture
async def client(app: FastAPI) -> AsyncClient:  # Changed to async fixture and AsyncClient
    """Create an async test client for the FastAPI app."""
    from httpx._transports.asgi import ASGITransport
    
    # Define default headers with test JWT token
    headers = {
        "Authorization": f"Bearer {TEST_JWT_TOKEN}",
        "Content-Type": "application/json"
    }
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test", 
        headers=headers
    ) as ac:
        yield ac

@pytest.fixture
def sample_patient_id():
    """Create a sample patient ID."""
    return uuid4()

@pytest.fixture
def sample_status_response(sample_patient_id):
    """Create a sample digital twin status response dictionary."""
    now_iso = datetime.now(UTC).isoformat()
    return {
        "patient_id": str(sample_patient_id),
        "status": "partial",
        "completeness": 60,
        "components": {
            "symptom_forecasting": {
                "has_model": True,
                "last_updated": now_iso
            },
            "biometric_correlation": {
                "has_model": True,
                "last_updated": now_iso
            },
            "pharmacogenomics": {
                "service_available": True,
                "service_info": {
                    "version": "1.0.0"
                }
            }
        },
        "last_checked": now_iso
    }


@pytest.fixture
def sample_insights_response(sample_patient_id):
    """Create a sample patient insights response dictionary."""
    now_iso = datetime.now(UTC).isoformat()
    # Using the structure from PersonalizedInsightResponse schema
    return {
        "patient_id": str(sample_patient_id),
        "generated_at": now_iso,
        "symptom_forecasting": {
            "trending_symptoms": [ # Corrected list structure
                {
                    "symptom": "anxiety",
                    "trend": "increasing",
                    "confidence": 0.85,
                    "insight_text": "Anxiety levels have been trending upward over the past week"
                }
            ],
            "risk_alerts": [ # Corrected list structure
                {
                    "symptom": "insomnia",
                    "risk_level": "moderate",
                    "alert_text": "Sleep disruption patterns indicate potential insomnia risk",
                    "importance": 0.75
                }
            ]
        },
        "biometric_correlation": {
            "strong_correlations": [ # Corrected list structure
                {
                    "biometric_type": "heart_rate",
                    "mental_health_indicator": "anxiety",
                    "correlation_strength": 0.82,
                    "direction": "positive",
                    "insight_text": "Elevated heart rate strongly correlates with reported anxiety",
                    "p_value": 0.01
                }
            ]
        },
        "pharmacogenomics": {
            "medication_responses": { # Assuming this structure based on schema
                "predictions": [ # Corrected list structure
                    {
                        "medication": "sertraline",
                        "predicted_response": "positive",
                        "confidence": 0.78
                    }
                ]
            }
        },
        "integrated_recommendations": [ # Corrected list structure
            {
                "source": "integrated",
                "type": "biometric_symptom",
                "recommendation": "Monitor heart rate as it correlates with anxiety levels",
                "importance": 0.85
            }
        ]
    }

# Fixture for PersonalizedInsightResponse
@pytest.fixture
def sample_personalized_insight_response(sample_patient_id):
    """Create a sample response conforming to PersonalizedInsightResponse."""
    now = datetime.now(UTC)
    return {
        "insight_id": str(uuid4()),
        "digital_twin_id": str(sample_patient_id), # Use patient_id as twin_id for simplicity
        "patient_id": str(sample_patient_id),
        "query": "Summarize recent mood changes.",
        "insight_type": "clinical",
        "insight": "Patient mood shows slight improvement over the past week, but anxiety spikes remain.",
        "key_points": [
            "Slight mood improvement noted.",
            "Anxiety spikes persist.",
            "Correlation with sleep patterns observed."
        ],
        "confidence": 0.88,
        "timestamp": now.isoformat(), # Use ISO format string for JSON compatibility
        "generated_at": now.isoformat()
    }

# Fixtures for clinical text analysis
@pytest.fixture
def sample_clinical_text_analysis_response():
    """Create a sample clinical text analysis response."""
    return {
        "analysis_type": "summary",
        "result": "Patient presents with increasing anxiety symptoms over the past week, with associated sleep disturbance.",
        "confidence": 0.9,
        "insights": [
            "Anxiety symptoms increasing",
            "Sleep pattern disruption noted",
            "Potential correlation with recent life events"
        ],
        "metadata": {
            "processing_time_ms": 254,
            "model_version": "mentallama-v2.1"
        }
    }

# Create a timeout decorator to prevent hanging
def timeout_handler(signum, frame):
    raise TimeoutError("Test execution timed out")

def with_timeout(seconds=5):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Set the timeout handler
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                result = await func(*args, **kwargs)
                # Cancel the alarm if the function completes normally
                signal.alarm(0)
                return result
            except Exception as e:
                # Cancel the alarm if an exception is raised
                signal.alarm(0)
                raise e
        return wrapper
    return decorator

# Tests
class TestDigitalTwinsEndpoints:
    """Tests for the digital twin endpoints."""

    @pytest.mark.asyncio
    async def test_get_twin_status(self, client, mock_digital_twin_service, sample_patient_id, sample_status_response):
        """Test GET /digital-twins/digital-twin/{patient_id}/status"""
        # Clone the sample response to avoid modifying the fixture
        status_response = sample_status_response.copy()
        
        # Set up mock return value - This is what the service implementation would return
        # We're now defining it to exactly match what the test expects
        mock_digital_twin_service.get_digital_twin_status.return_value = status_response
        
        # Make request with corrected path
        response = await client.get(f"/api/v1/digital-twins/digital-twin/{sample_patient_id}/status")
        
        # Print both for debugging
        print("\nActual response:", response.json())
        print("\nExpected response:", status_response)
        
        # Assert response
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == status_response
        mock_digital_twin_service.get_digital_twin_status.assert_called_once_with(patient_id=sample_patient_id)

    @pytest.mark.asyncio
    async def test_get_twin_status_not_found(self, client, mock_digital_twin_service, sample_patient_id):
        """Test GET /digital-twins/digital-twin/{patient_id}/status with not found error."""
        # Setup the mock to raise ResourceNotFoundError
        mock_digital_twin_service.get_digital_twin_status.side_effect = ResourceNotFoundError(f"No digital twin found for patient {sample_patient_id}")

        # Make request with corrected path
        response = await client.get(f"/api/v1/digital-twins/digital-twin/{sample_patient_id}/status")
        
        # Assert response
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()
        mock_digital_twin_service.get_digital_twin_status.assert_called_once_with(patient_id=sample_patient_id)

    @pytest.mark.asyncio
    async def test_get_comprehensive_insights(self, client, mock_digital_twin_service, sample_patient_id, sample_personalized_insight_response):
        """Test GET /digital-twins/digital-twin/{patient_id}/insights with successful response."""
        # Clone the sample response to avoid modifying the fixture
        insight_response = sample_personalized_insight_response.copy()
        
        # Setup the mock return value - exactly matching what the test expects
        mock_digital_twin_service.generate_comprehensive_patient_insights.return_value = insight_response
        
        # Make request with corrected path
        response = await client.get(f"/api/v1/digital-twins/digital-twin/{sample_patient_id}/insights")
        
        # Print both for debugging
        print("\nActual insights response:", response.json())
        print("\nExpected insights response:", insight_response)
        
        # Assert response
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == insight_response
        mock_digital_twin_service.generate_comprehensive_patient_insights.assert_called_once_with(patient_id=sample_patient_id)

    @pytest.mark.asyncio
    async def test_get_comprehensive_insights_error(
        self,
        client: AsyncClient,
        mock_digital_twin_service: AsyncMock,
        sample_patient_id: UUID
    ):
        """Test error handling for comprehensive insights generation."""
        # Configure the mock to raise our custom exception
        mock_digital_twin_service.generate_comprehensive_patient_insights.side_effect = ModelExecutionError("Service unavailable")

        # Define endpoint path
        insights_url = f"/api/v1/digital-twins/digital-twin/{sample_patient_id}/insights"

        # Create a simple client to test with different settings
        from httpx import AsyncClient
        from fastapi.testclient import TestClient
        from app.app_factory import create_application
        
        settings = client.base_url
        app_test = create_application(include_test_routers=False, skip_auth_middleware=True)
        
        # Add the same dependency overrides
        from app.presentation.api.v1.dependencies.digital_twin import get_digital_twin_service
        app_test.dependency_overrides[get_digital_twin_service] = lambda: mock_digital_twin_service
        
        from app.presentation.api.dependencies.auth import get_current_user, get_current_active_user
        from app.tests.unit.presentation.api.v1.endpoints.test_digital_twins import mock_current_user
        app_test.dependency_overrides[get_current_user] = lambda: mock_current_user
        app_test.dependency_overrides[get_current_active_user] = lambda: mock_current_user
        
        from app.presentation.api.v1.routes.digital_twin import router
        app_test.include_router(router, prefix="/api/v1/digital-twins")
        
        test_client = TestClient(app_test)
        response = test_client.get(insights_url)
        
        # Verify the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        content = response.json()
        assert "detail" in content
        assert "An unexpected internal server error occurred." in content["detail"]
        assert content.get("error_code") == "INTERNAL_SERVER_ERROR"
        
        # Verify the mock was called
        mock_digital_twin_service.generate_comprehensive_patient_insights.assert_called_once_with(patient_id=sample_patient_id)

    @pytest.mark.asyncio
    async def test_analyze_clinical_text(self, client, mock_digital_twin_service, sample_patient_id, sample_clinical_text_analysis_response):
        """Test POST /digital-twins/digital-twin/{patient_id}/analyze-text with successful analysis."""
        # Setup the mock return value
        mock_digital_twin_service.analyze_clinical_text_mentallama.return_value = sample_clinical_text_analysis_response
        
        # Prepare request body
        request_data = {
            "text": "Patient reports increasing anxiety with sleep disturbance",
            "analysis_type": "summary"
        }
        
        # Make request with corrected path
        response = await client.post(
            f"/api/v1/digital-twins/digital-twin/{sample_patient_id}/analyze-text",
            json=request_data
        )
        
        # Assert response
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == sample_clinical_text_analysis_response
        mock_digital_twin_service.analyze_clinical_text_mentallama.assert_called_once_with(
            patient_id=sample_patient_id,
            text=request_data["text"],
            analysis_type=request_data["analysis_type"]
        )

    @pytest.mark.asyncio
    async def test_analyze_clinical_text_validation_error(self, client, sample_patient_id):
        """Test POST /digital-twins/digital-twin/{patient_id}/analyze-text with validation error."""
        # Prepare invalid request body (missing required text field)
        request_data = {
            "analysis_type": "summary"  # Missing required "text" field
        }
        
        # Make request with corrected path
        response = await client.post(
            f"/api/v1/digital-twins/digital-twin/{sample_patient_id}/analyze-text",
            json=request_data
        )
        
        # Assert response
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_analyze_clinical_text_service_error(
        self,
        client: AsyncClient,
        mock_digital_twin_service: AsyncMock,
        sample_patient_id: UUID
    ):
        """Test error handling when MentaLLaMA service fails for clinical text analysis."""
        # Test data
        valid_payload_for_service_call = {
            "text": "Patient reports feeling anxious.",
            "analysis_type": "summary"
        }
        
        # Configure the mock to raise our custom exception
        mock_digital_twin_service.analyze_clinical_text_mentallama.side_effect = ModelExecutionError("MentaLLaMA service error")

        # Define endpoint path
        analysis_url = f"/api/v1/digital-twins/digital-twin/{sample_patient_id}/analyze-text"
        
        # Create a simple client to test with different settings
        from httpx import AsyncClient
        from fastapi.testclient import TestClient
        from app.app_factory import create_application
        
        settings = client.base_url
        app_test = create_application(include_test_routers=False, skip_auth_middleware=True)
        
        # Add the same dependency overrides
        from app.presentation.api.v1.dependencies.digital_twin import get_digital_twin_service
        app_test.dependency_overrides[get_digital_twin_service] = lambda: mock_digital_twin_service
        
        from app.presentation.api.dependencies.auth import get_current_user, get_current_active_user
        from app.tests.unit.presentation.api.v1.endpoints.test_digital_twins import mock_current_user
        app_test.dependency_overrides[get_current_user] = lambda: mock_current_user
        app_test.dependency_overrides[get_current_active_user] = lambda: mock_current_user
        
        from app.presentation.api.v1.routes.digital_twin import router
        app_test.include_router(router, prefix="/api/v1/digital-twins")
        
        test_client = TestClient(app_test)
        response = test_client.post(analysis_url, json=valid_payload_for_service_call)
        
        # Verify the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        content = response.json()
        assert "detail" in content
        assert "An unexpected internal server error occurred." in content["detail"]
        assert content.get("error_code") == "INTERNAL_SERVER_ERROR"
        
        # Verify the mock was called
        mock_digital_twin_service.analyze_clinical_text_mentallama.assert_called_once_with(
            patient_id=sample_patient_id, 
            text=valid_payload_for_service_call["text"],
            analysis_type=valid_payload_for_service_call["analysis_type"]
        )


# Add tests for other endpoints (/forecast, /correlations, /medication-response, /treatment-plan)
# following a similar pattern: setup mock, make request, assert response and mock calls.
# ...
