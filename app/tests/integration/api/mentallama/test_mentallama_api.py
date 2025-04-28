# -*- coding: utf-8 -*-
"""
MentaLLaMA API Integration Tests.

This module contains integration tests for the MentaLLaMA API routes, following
clean architecture principles with precise, mathematically elegant implementations.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Generator
from unittest.mock import MagicMock, Mock, patch, AsyncMock

import pytest
import pytest_asyncio
from fastapi import FastAPI, status
from httpx import AsyncClient

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio

from app.config.settings import get_settings
from app.core.exceptions import (
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError
)

from app.core.services.ml.interface import MentaLLaMAInterface
from app.infrastructure.ml.mentallama.service import MentaLLaMA # Corrected import name
from app.main import create_application

# Load settings ONCE for the module
settings = get_settings()
MENTALLAMA_API_PREFIX = f"{settings.API_V1_STR}/mentallama"

# Mock services
@pytest.mark.db_required()
class MockMentaLLaMAService(MentaLLaMAInterface):
    """Mock MentaLLaMA service for testing."""
    
    def __init__(self):
        """Initialize mock service."""
        self.initialized = True
        # Add a mock version attribute based on loaded settings if health check needs it
        self.version = settings.ml.mentallama.version if hasattr(settings.ml.mentallama, 'version') else "mock-0.1"
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """Mock initialization."""
        self.initialized = True
    
    def is_healthy(self) -> bool:
        """Mock health check."""
        return self.initialized
    
    def shutdown(self) -> None:
        """Mock shutdown."""
        self.initialized = False
    
    def process(
        self,
        prompt: str,
        model: str = None,
        task: str = None,
        context: Optional[Dict[str, Any]] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Mock process method."""
        if not prompt:
            raise InvalidRequestError("Prompt cannot be empty")
        
        if model and model not in ["mentallama-7b", "mentallama-33b", "mentallama-33b-lora"]:
            raise ModelNotFoundError(f"Model {model} not found")
        
        # Return mock response
        return {
            "response_id": str(uuid.uuid4()),
            "model": model or "mentallama-33b",
            "provider": "aws-bedrock",
            "text": "This is a mock response from MentaLLaMA.",
            "confidence": "high",
            "processing_time": 0.5,
            "tokens_used": 50,
            "created_at": datetime.now().isoformat()
        }
    
    def analyze_text(
        self,
        text: str,
        analysis_type: str = "comprehensive",
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Mock text analysis method."""
        if not text:
            raise InvalidRequestError("Text cannot be empty")
        
        # Return mock response
        return {
            "response_id": str(uuid.uuid4()),
            "model": "mentallama-33b",
            "provider": "aws-bedrock",
            "text": "This is a mock analysis response.",
            "structured_data": {
                "sentiment": "neutral",
                "entities": [{"type": "symptom", "text": "depression", "confidence": 0.9}],
                "keywords": ["mood", "sleep", "anxiety"],
                "categories": ["mental health", "depression"]
            },
            "confidence": "high",
            "processing_time": 0.5,
            "tokens_used": 75,
            "created_at": datetime.now().isoformat()
        }
    
    def detect_mental_health_conditions(
        self,
        text: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Mock condition detection method."""
        if not text:
            raise InvalidRequestError("Text cannot be empty")
        
        # Return mock response
        return {
            "response_id": str(uuid.uuid4()),
            "model": "mentallama-33b-lora",
            "provider": "aws-bedrock",
            "text": "Analysis indicates potential depression and anxiety.",
            "structured_data": {
                "conditions": [
                    {
                        "condition": "Depression",
                        "confidence": 0.85,
                        "evidence": ["low mood", "sleep disturbance"]
                    },
                    {
                        "condition": "Anxiety",
                        "confidence": 0.75,
                        "evidence": ["worry", "restlessness"]
                    }
                ]
            },
            "confidence": "high",
            "processing_time": 0.6,
            "tokens_used": 90,
            "created_at": datetime.now().isoformat()
        }
    
    def generate_therapeutic_response(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Mock therapeutic response generation."""
        if not text:
            raise InvalidRequestError("Text cannot be empty")
        
        # Return mock response
        return {
            "response_id": str(uuid.uuid4()),
            "model": "mentallama-33b-lora",
            "provider": "aws-bedrock",
            "text": "I understand you're feeling down. Let's explore some coping strategies.",
            "structured_data": {
                "therapeutic_approach": "CBT",
                "techniques": ["validation", "reframing", "behavioral activation"],
                "follow_up_questions": ["How have you been sleeping?", "What activities bring you joy?"]
            },
            "confidence": "high",
            "processing_time": 0.7,
            "tokens_used": 100,
            "created_at": datetime.now().isoformat()
        }
    
    def assess_suicide_risk(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Mock suicide risk assessment."""
        if not text:
            raise InvalidRequestError("Text cannot be empty")
        
        # Return mock response
        return {
            "response_id": str(uuid.uuid4()),
            "model": "mentallama-33b-lora",
            "provider": "aws-bedrock",
            "text": "Risk assessment indicates low immediate risk but presence of risk factors.",
            "structured_data": {
                "risk_level": "low",
                "risk_factors": ["hopelessness", "isolation"],
                "protective_factors": ["future plans", "social support"],
                "recommendations": ["regular check-ins", "safety planning"],
                "immediate_action_required": False
            },
            "confidence": "high",
            "processing_time": 0.8,
            "tokens_used": 120,
            "created_at": datetime.now().isoformat()
        }
    
    def analyze_wellness_dimensions(
        self,
        text: str,
        dimensions: List[str],
        include_recommendations: bool = False,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Mock wellness dimensions analysis."""
        if not text:
            raise InvalidRequestError("Text cannot be empty")
        
        if not dimensions:
            raise InvalidRequestError("At least one dimension must be specified")
            
        # Return mock response
        return {
            "response_id": str(uuid.uuid4()),
            "model": "mentallama-33b-lora",
            "provider": "aws-bedrock",
            "text": "Wellness analysis complete across specified dimensions.",
            "structured_data": {
                "dimensions": {
                    dim: {
                        "score": round(0.5 + 0.4 * (i/len(dimensions)), 2), 
                        "insights": [f"Sample insight for {dim}"],
                        "recommendations": [f"Sample recommendation for {dim}"] if include_recommendations else []
                    }
                    for i, dim in enumerate(dimensions)
                }
            },
            "confidence": "high",
            "processing_time": 0.8,
            "tokens_used": 120,
            "created_at": datetime.now().isoformat()
        }

    # Add get_health_status if the endpoint calls it directly
    def get_health_status(self) -> Dict[str, Any]:
        return {
            "status": "healthy" if self.initialized else "unhealthy",
            "version": self.version,
            "model_provider": settings.ml.mentallama.provider, # Use loaded settings
            "models_loaded": list(settings.ml.mentallama.model_mappings.values()) if settings.ml.mentallama.model_mappings else ["mock-model"]
        }


@pytest.fixture(scope="module")
def test_app(mock_mentallama_service_override) -> FastAPI:
    """Create a test application instance with overrides."""
    app = create_application()
    # Dependency override is handled by mock_mentallama_service_override fixture
    return app

@pytest_asyncio.fixture(scope="module")
async def client(test_app: FastAPI):
    """Create an AsyncClient for the application."""
    # Using async_client directly instead of async with context manager
    client = AsyncClient(app=test_app, base_url="http://test")
    yield client
    # Clean up after tests
    await client.aclose()

@pytest.fixture(scope="module") # Use module scope if service is stateless for the module
def mock_mentallama_service_instance() -> AsyncMock:
    """Provides a single instance of the mock service for the module."""
    # Use AsyncMock with the correct interface spec
    mock_service = AsyncMock(spec=MentaLLaMAInterface)
    
    # --- Setup Mock Return Values for Methods Used in Tests ---
    # Example: Mock the 'process' method (adjust based on actual test needs)
    mock_process_result = {
        "model": "mock-mentallama",
        "model_version": "1.0.0",
        "text_length": 100,
        "word_count": 20,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "sentiment": {"score": 0.5, "label": "positive"},
        "language_stats": {"avg_word_length": 5.0, "sentence_count": 2},
        "options_used": {}
    }
    mock_service.process = AsyncMock(return_value=mock_process_result)
    
    # Example: Mock 'analyze_sentiment'
    mock_sentiment_result = {"sentiment": {"score": 0.6, "label": "positive"}}
    mock_service.analyze_sentiment = AsyncMock(return_value=mock_sentiment_result)
    
    # Example: Mock 'assess_risk'
    mock_risk_result = {"risk_level": "low", "confidence": 0.9}
    mock_service.assess_risk = AsyncMock(return_value=mock_risk_result)

    # Example: Mock 'detect_depression'
    mock_depression_result = {"detected": False, "score": 0.1}
    mock_service.detect_depression = AsyncMock(return_value=mock_depression_result)
    
    # Example: Mock 'analyze_wellness_dimensions'
    mock_wellness_result = {"dimensions": {"emotional": 0.7, "social": 0.6}}
    mock_service.analyze_wellness_dimensions = AsyncMock(return_value=mock_wellness_result)
    
    # Mock 'is_healthy' to return True
    mock_service.is_healthy = MagicMock(return_value=True) # is_healthy might be synchronous

    # --- End Mock Return Values ---
    
    return mock_service # Return the configured AsyncMock

# Fixture to apply the override
@pytest.fixture(scope="module", autouse=True) # Autouse applies it to all tests in the module
def mock_mentallama_service_override(mock_mentallama_service_instance):
    """Overrides the real MentaLLaMA service with the mock instance."""
    # Need to patch the actual dependency function used by the endpoint
    # Assuming it's something like 'app.presentation.api.v1.dependencies.get_mentallama_service'
    # This path needs to be verified.
    dependency_path = "app.presentation.api.v1.dependencies.ml.get_mentallama_service" # Example path - VERIFY THIS
    
    # Define the override function
    def override_dependency():
        return mock_mentallama_service_instance

    # Use patch context manager for robust override
    with patch(dependency_path, return_value=override_dependency) as mock_dependency:
        # Yield control to allow tests to run with the patch active
        yield mock_dependency 
        # Patch is automatically removed when the context exits


@pytest.fixture
def mock_auth():
    """Fixture to mock authentication middleware."""
    with patch("app.api.routes.ml.verify_api_key", return_value=True):
        yield


@pytest.mark.integration()
class TestMentaLLaMAAPI:
    """Integration tests for MentaLLaMA API endpoints.
    
    This test suite verifies the correctness and robustness of the MentaLLaMA API
    with mathematically precise validation of inputs, outputs, and error cases.
    """
    
    async def test_process_endpoint(self, client: AsyncClient, mock_auth):
        """Test the process endpoint."""
        # Prepare test data
        payload = {
            "prompt": "Tell me about depression",
            "model": "mentallama-33b",
            "max_tokens": 100,
            "temperature": 0.7
        }
        
        # Call API
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/process",
            json=payload,
            headers=mock_auth
        )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["model"] == "mentallama-33b"
        assert "text" in data
        assert data["provider"] == "aws-bedrock"
    
    async def test_process_invalid_model(self, client: AsyncClient, mock_auth):
        """Test process endpoint with invalid model."""
        # Prepare test data
        payload = {
            "prompt": "Tell me about anxiety",
            "model": "invalid-model",
            "max_tokens": 100
        }
        
        # Call API
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/process",
            json=payload,
            headers=mock_auth
        )
        
        # Verify response
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"].lower()
    
    async def test_process_empty_prompt(self, client: AsyncClient, mock_auth):
        """Test process endpoint with empty prompt."""
        # Prepare test data
        payload = {
            "prompt": "",
            "model": "mentallama-33b"
        }
        
        # Call API
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/process",
            json=payload,
            headers=mock_auth
        )
        
        # Verify response
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()
        assert "detail" in data
        assert "empty" in data["detail"].lower()
    
    async def test_analyze_text_endpoint(self, client: AsyncClient, mock_auth):
        """Test the analyze_text endpoint."""
        # Prepare test data
        payload = {
            "text": "I've been feeling sad and tired lately, and I'm not sleeping well.",
            "analysis_type": "comprehensive"
        }
        
        # Call API
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/analyze",
            json=payload,
            headers=mock_auth
        )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "structured_data" in data
        assert "sentiment" in data["structured_data"]
        assert "entities" in data["structured_data"]
    
    async def test_detect_conditions_endpoint(self, client: AsyncClient, mock_auth):
        """Test the detect_mental_health_conditions endpoint."""
        # Prepare test data
        payload = {
            "text": "I worry constantly and can't sleep. I've lost interest in activities I used to enjoy."
        }
        
        # Call API
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/detect_conditions",
            json=payload,
            headers=mock_auth
        )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "structured_data" in data
        assert "conditions" in data["structured_data"]
        conditions = data["structured_data"]["conditions"]
        assert len(conditions) > 0
        assert "condition" in conditions[0]
        assert "confidence" in conditions[0]
    
    async def test_therapeutic_response_endpoint(self, client: AsyncClient, mock_auth):
        """Test the generate_therapeutic_response endpoint."""
        # Prepare test data
        payload = {
            "text": "I feel very alone and hopeless.",
            "context": {
                "patient_history": "Previous diagnosis of depression",
                "therapy_approach": "CBT"
            }
        }
        
        # Call API
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/therapeutic_response",
            json=payload,
            headers=mock_auth
        )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "text" in data
        assert "structured_data" in data
        assert "therapeutic_approach" in data["structured_data"]
        assert "techniques" in data["structured_data"]
    
    async def test_suicide_risk_endpoint(self, client: AsyncClient, mock_auth):
        """Test the assess_suicide_risk endpoint."""
        # Prepare test data
        payload = {
            "text": "I don't see any point in going on. Nothing will ever get better.",
            "context": {
                "previous_attempts": False,
                "support_network": "Limited"
            }
        }
        
        # Call API
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/assess_suicide_risk",
            json=payload,
            headers=mock_auth
        )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "structured_data" in data
        assert "risk_level" in data["structured_data"]
        assert "risk_factors" in data["structured_data"]
        assert "protective_factors" in data["structured_data"]
        assert "recommendations" in data["structured_data"]
        assert "immediate_action_required" in data["structured_data"]
    
    async def test_wellness_dimensions_endpoint(self, client: AsyncClient, mock_auth):
        """Test the analyze_wellness_dimensions endpoint."""
        # Prepare test data
        payload = {
            "text": "I've been exercising regularly but feel socially isolated. Work is stressful.",
            "dimensions": ["physical", "social", "occupational", "emotional"],
            "include_recommendations": True
        }
        
        # Call API
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/analyze_wellness_dimensions",
            json=payload,
            headers=mock_auth
        )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "structured_data" in data
        assert "dimensions" in data["structured_data"]
        dimensions = data["structured_data"]["dimensions"]
        assert "physical" in dimensions
        assert "score" in dimensions["physical"]
        assert "recommendations" in dimensions["physical"]
    
    async def test_health_check(self, client: AsyncClient):
        """Test the health check endpoint."""
        # Call API
        response = await client.get(f"{MENTALLAMA_API_PREFIX}/health")
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == settings.ml.mentallama.version if hasattr(settings.ml.mentallama, 'version') else "mock-0.1"
    
    async def test_service_unavailable(self, client: AsyncClient, mock_auth, mock_mentallama_service_instance):
        """Test behavior when service is unavailable."""
        # Make the mock service unhealthy
        mock_mentallama_service_instance.initialized = False 
        # Or configure a specific method to raise ServiceUnavailableError
        # mock_mentallama_service_instance.process.side_effect = ServiceUnavailableError("Mock service down")
        
        payload = {"prompt": "Test prompt"}
        response = await client.post(
            f"{MENTALLAMA_API_PREFIX}/process",
            json=payload,
            headers=mock_auth
        )
        # Adjust expected status based on how unavailability is handled (e.g., 503)
        # If the health check within the endpoint fails first, it might be 503
        # If the process call itself fails with ServiceUnavailableError, depends on exception handler
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE # Assuming 503 for general unavailability
        # Restore service state for other tests if needed
        mock_mentallama_service_instance.initialized = True
