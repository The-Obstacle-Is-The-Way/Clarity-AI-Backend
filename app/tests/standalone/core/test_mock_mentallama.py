"""
Unit tests for MockMentaLLaMA service.

This module tests the mock implementation of the MentaLLaMA service,
ensuring it correctly implements the interface and provides consistent
behavior for testing purposes. The tests verify initialization, error handling,
and all core psychiatry analysis features.
"""

import asyncio
from unittest.mock import MagicMock

import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

from app.core.exceptions import (
    InvalidRequestError,
    ServiceUnavailableError,
)

# Import the mock service and the interface it implements
from app.infrastructure.ml.mentallama.mock_service import MockMentaLLaMA

# Import PHI service needed for mock init
from app.infrastructure.ml.phi_detection.service import PHIDetectionService


@pytest.fixture(scope="function")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    # The loop should be closed at the end of the test
    loop.close()


@pytest.fixture(scope="function")
def mock_mentallama_service_standalone(request):
    """Pytest fixture to set up and tear down MockMentaLLaMA for each standalone test."""
    # Mock the required PHI service dependency for MockMentaLLaMA's __init__
    mock_phi_service = MagicMock(spec=PHIDetectionService)
    mock_phi_service.contains_phi.return_value = False
    mock_phi_service.redact_phi.side_effect = lambda x: x
    
    # Instantiate the mock service
    service = MockMentaLLaMA(phi_detection_service=mock_phi_service)
    # Initialize using the interface method
    service.initialize({"model_name": "test-mock-model"}) # Pass some basic config
    
    sample_text = (
        "I've been feeling down for several weeks. I'm constantly tired, "
        "have trouble sleeping, and don't enjoy things anymore. Sometimes "
        "I wonder if life is worth living, but I wouldn't actually hurt myself."
    )
    
    # Store service and common data on the test instance via request
    request.instance.service = service
    request.instance.sample_text = sample_text
    
    yield service # Provide the service to the test function

    # Teardown: Shutdown the service
    if hasattr(request.instance, "service") and request.instance.service.is_healthy():
        request.instance.service.shutdown()


@pytest.mark.usefixtures("mock_mentallama_service_standalone")
# Remove db_required mark if not actually needed for mock tests
# @pytest.mark.db_required()
@pytest.mark.usefixtures("mock_mentallama_service_standalone")
class TestMockMentaLLaMA:
    """Test suite for MockMentaLLaMA class."""

    # Keep initialization test, adapt if necessary
    @pytest.mark.standalone()
    def test_initialization(self, mock_phi_service) -> None: # Add mock_phi_service fixture
        """Test initialization of the mock service."""
        # Test initialization via constructor and initialize method
        service = MockMentaLLaMA(phi_detection_service=mock_phi_service)
        assert not service.is_healthy() # Should not be healthy before initialize
        service.initialize({"model_name": "test-model"})
        assert service.is_healthy()
        assert service._model_name == "test-model"
        # Add more specific checks if the mock's initialize does more

    # Keep health check test
    @pytest.mark.standalone()
    def test_health_check(self) -> None:
        """Test health check functionality."""
        assert self.service.is_healthy() # Should be healthy from fixture
        self.service.shutdown()
        assert not self.service.is_healthy()

    # --- Test Interface Methods ---

    @pytest.mark.standalone()
    @pytest.mark.asyncio
    async def test_process_general(self) -> None:
        """Test the process method for general analysis."""
        result = await self.service.process(text=self.sample_text, model_type="general")
        assert isinstance(result, dict)
        assert result["metadata"]["analysis_type"] == "general"
        assert "insights" in result["analysis"]

    @pytest.mark.standalone()
    @pytest.mark.asyncio
    async def test_process_risk_assessment(self) -> None:
        """Test the process method for risk assessment."""
        result = await self.service.process(text=self.sample_text, model_type="risk_assessment")
        assert isinstance(result, dict)
        assert result["metadata"]["analysis_type"] == "risk_assessment"
        assert "risk_level" in result["analysis"]

    @pytest.mark.standalone()
    @pytest.mark.asyncio
    async def test_process_empty_text(self) -> None:
        """Test process method with empty text."""
        with pytest.raises(InvalidRequestError):
            await self.service.process(text="")

    @pytest.mark.standalone()
    @pytest.mark.asyncio
    async def test_process_not_initialized(self) -> None:
        """Test process method when service is not initialized."""
        self.service.shutdown() # Ensure it's not initialized
        with pytest.raises(ServiceUnavailableError):
             await self.service.process(text=self.sample_text)

    @pytest.mark.standalone()
    @pytest.mark.asyncio
    async def test_detect_depression_positive(self) -> None:
        """Test detect_depression method - positive case."""
        result = await self.service.detect_depression(text=self.sample_text)
        assert isinstance(result, dict)
        assert result["detected"] is True
        assert result["confidence"] > 0.5

    @pytest.mark.standalone()
    @pytest.mark.asyncio
    async def test_detect_depression_negative(self) -> None:
        """Test detect_depression method - negative case."""
        result = await self.service.detect_depression(text="Feeling great today!")
        assert isinstance(result, dict)
        assert result["detected"] is False
        assert result["confidence"] < 0.5

    @pytest.mark.standalone()
    @pytest.mark.asyncio
    async def test_detect_depression_empty_text(self) -> None:
        """Test detect_depression method with empty text."""
        with pytest.raises(InvalidRequestError):
            await self.service.detect_depression(text="")

    # Remove all other test methods that call non-interface methods
    # (e.g., test_analyze_text, test_detect_mental_health_conditions, etc.)
