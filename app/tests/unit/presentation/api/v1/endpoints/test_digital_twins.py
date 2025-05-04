"""
Unit tests for Digital Twin API endpoints.

Tests the API endpoints for Digital Twin functionality, including
the MentaLLaMA integration for clinical text processing.
"""
# Standard Library Imports
from datetime import datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

# Third-Party Imports
import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

# First-Party Imports (Organized)
# Assuming base exceptions are in core.exceptions.base_exceptions
from app.core.exceptions.base_exceptions import (
    ModelExecutionError,  # Changed from ModelInferenceError
    ResourceNotFoundError,
)
from app.domain.entities.user import User  # Added User import
from app.presentation.api.dependencies.auth import get_current_user  # Standard auth dependency

# Import domain entities/services - Adjust paths if necessary
# from app.infrastructure.ml.digital_twin_integration_service import DigitalTwinIntegrationService # Use for spec if needed
# Import presentation layer components
from app.presentation.api.dependencies.services import (
    get_digital_twin_service,
)
from app.presentation.api.v1.endpoints.digital_twins import router as digital_twins_router
from app.presentation.api.schemas.digital_twin_schemas import (
    ClinicalTextAnalysisResponse,
    PersonalizedInsightResponse,
)

# Define UTC timezone
UTC = timedelta(0) # Simple UTC offset

# Fixtures
@pytest.fixture
def mock_digital_twin_service():
    """Create a mock DigitalTwinIntegrationService."""
    # service = AsyncMock(spec=DigitalTwinIntegrationService) # Use spec if class is available
    service = AsyncMock() # Use basic AsyncMock if spec import is problematic

    # Mock top-level methods
    service.get_digital_twin_status = AsyncMock()
    service.generate_comprehensive_patient_insights = AsyncMock()
    service.update_digital_twin = AsyncMock() # Assuming an update method exists
    service.analyze_clinical_text_mentallama = AsyncMock() # Assuming this method exists for the endpoint

    # Mock nested/underlying services if methods are called directly (unlikely based on endpoint structure)
    # service.mentallama_service = AsyncMock() 
    # service.symptom_forecasting_service = AsyncMock()
    # service.biometric_correlation_service = AsyncMock()
    # service.pharmacogenomics_service = AsyncMock()
    
    return service

@pytest.fixture
def mock_current_user():
    """Fixture for a mock User object."""
    return User(id=UUID("00000000-0000-0000-0000-000000000001"), role="admin", email="test@example.com")

@pytest.fixture
def app(mock_digital_twin_service, mock_current_user):
    """Create a FastAPI test application."""
    app_instance = FastAPI()

    # Override dependencies
    app_instance.dependency_overrides[get_digital_twin_service] = lambda: mock_digital_twin_service
    app_instance.dependency_overrides[get_current_user] = lambda: mock_current_user

    # Include router
    app_instance.include_router(digital_twins_router)
    return app_instance

@pytest.fixture
def client(app):
    """Create a test client for the FastAPI app."""
    return TestClient(app)

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
        "query": "Summarize recent mood changes.",
        "insight_type": "clinical",
        "insight": "Patient mood shows slight improvement over the past week, but anxiety spikes remain.",
        "key_points": [
            "Slight mood improvement noted.",
            "Anxiety spikes persist.",
            "Correlation with sleep patterns observed."
        ],
        "confidence": 0.88,
        "timestamp": now.isoformat() # Use ISO format string for JSON compatibility
    }

# Fixtures for other response types (forecast, correlation, pgx) can be added if needed
# ...

# Tests
class TestDigitalTwinsEndpoints:
    """Tests for the digital twin endpoints."""

    @pytest.mark.asyncio
    async def test_get_twin_status(self, client, mock_digital_twin_service, sample_patient_id, sample_status_response):
        """Test GET /digital-twins/{patient_id}/status"""
        mock_digital_twin_service.get_digital_twin_status.return_value = sample_status_response
        
        response = await client.get(f"/digital-twins/{sample_patient_id}/status")
        
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == sample_status_response
        mock_digital_twin_service.get_digital_twin_status.assert_called_once_with(sample_patient_id)

    @pytest.mark.asyncio
    async def test_get_twin_status_not_found(self, client, mock_digital_twin_service, sample_patient_id):
        """Test GET /digital-twins/{patient_id}/status for not found"""
        mock_digital_twin_service.get_digital_twin_status.side_effect = ResourceNotFoundError("Status not found")
        
        response = await client.get(f"/digital-twins/{sample_patient_id}/status")
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_get_comprehensive_insights(self, client, mock_digital_twin_service, sample_patient_id, sample_personalized_insight_response):
        """Test GET /digital-twins/{patient_id}/insights"""
        mock_digital_twin_service.generate_comprehensive_patient_insights.return_value = sample_personalized_insight_response
        
        response = await client.get(f"/digital-twins/{sample_patient_id}/insights")
        
        assert response.status_code == status.HTTP_200_OK
        # Validate response against Pydantic schema
        parsed_response = PersonalizedInsightResponse.model_validate(response.json())
        assert parsed_response.digital_twin_id == str(sample_patient_id)
        assert parsed_response.insight_id == sample_personalized_insight_response["insight_id"]
        assert parsed_response.query == sample_personalized_insight_response["query"]
        assert parsed_response.timestamp.isoformat() == sample_personalized_insight_response["timestamp"]
        
        mock_digital_twin_service.generate_comprehensive_patient_insights.assert_called_once_with(sample_patient_id)

    @pytest.mark.asyncio
    async def test_get_comprehensive_insights_error(self, client, mock_digital_twin_service, sample_patient_id):
        """Test GET /digital-twins/{patient_id}/insights error handling"""
        mock_digital_twin_service.generate_comprehensive_patient_insights.side_effect = ModelExecutionError("Insight generation failed")
        
        response = await client.get(f"/digital-twins/{sample_patient_id}/insights")
        
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "Failed to generate insights" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_analyze_clinical_text(self, client, mock_digital_twin_service, sample_patient_id):
        """Test POST /digital-twins/{patient_id}/analyze-text"""
        request_data = {
            "text": "Patient reports feeling anxious and having trouble sleeping.",
            "analysis_type": "summary"
        }
        mock_response_data = {
            "analysis_type": "summary",
            "result": "The patient is experiencing anxiety and sleep difficulties.",
            "metadata": {"model": "mentallama-v1"}
        }
        mock_digital_twin_service.analyze_clinical_text_mentallama.return_value = mock_response_data
        
        response = await client.post(f"/digital-twins/{sample_patient_id}/analyze-text", json=request_data)
        
        assert response.status_code == status.HTTP_200_OK
        # Validate response against Pydantic schema if desired
        parsed_response = ClinicalTextAnalysisResponse.model_validate(response.json())
        assert parsed_response.result == mock_response_data["result"]
        
        mock_digital_twin_service.analyze_clinical_text_mentallama.assert_called_once_with(
            patient_id=sample_patient_id,
            text=request_data["text"],
            analysis_type=request_data["analysis_type"]
        )

    @pytest.mark.asyncio
    async def test_analyze_clinical_text_validation_error(self, client, sample_patient_id):
        """Test POST /digital-twins/{patient_id}/analyze-text with invalid input"""
        request_data = {"text": ""} # Missing analysis_type, empty text
        
        response = await client.post(f"/digital-twins/{sample_patient_id}/analyze-text", json=request_data)
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY # FastAPI validation error
    
    @pytest.mark.asyncio
    async def test_analyze_clinical_text_service_error(self, client, mock_digital_twin_service, sample_patient_id):
        """Test error handling for clinical text analysis."""
        # Setup - Simulate service error
        mock_digital_twin_service.analyze_clinical_text_mentallama.side_effect = ModelExecutionError("Inference failed")
        request_data = {"text": "Patient reports feeling anxious.", "data_source": "session_notes"}

        # Execute & Verify
        with pytest.raises(ModelExecutionError):
             client.post(f"/digital-twins/{sample_patient_id}/analyze-text", json=request_data)
        # Check the actual response status code based on how ModelExecutionError is handled by FastAPI exception handlers
        response = client.post(f"/digital-twins/{sample_patient_id}/analyze-text", json=request_data)
        # Assuming ModelExecutionError maps to 500 Internal Server Error by default or via handler
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR 
        assert "Inference failed" in response.json()["detail"] # Check if detail contains the error message


# Add tests for other endpoints (/forecast, /correlations, /medication-response, /treatment-plan)
# following a similar pattern: setup mock, make request, assert response and mock calls.
# ...
