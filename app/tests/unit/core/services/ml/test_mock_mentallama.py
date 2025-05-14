"""
Unit tests for MockMentaLLaMA service.

This module tests the mock implementation of the MentaLLaMA service,
ensuring it correctly implements the interface and provides consistent
behavior for testing purposes. The tests verify initialization, error handling,
and all core psychiatry analysis features.
"""

from datetime import datetime
import random

import pytest

from app.core.exceptions import (
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError,
)
from app.domain.utils.datetime_utils import UTC
from app.infrastructure.ml.mentallama.mock import MockMentaLLaMA  # Corrected import path


@pytest.fixture(scope="function")
def mock_mentallama_service(request):
    """Pytest fixture to set up and tear down MockMentaLLaMA for each test."""
    service = MockMentaLLaMA()
    service.initialize({})
    
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

@pytest.mark.usefixtures("mock_mentallama_service") # Apply the fixture
@pytest.mark.db_required() # Keep existing marker
class TestMockMentaLLaMA:
    """Test suite for MockMentaLLaMA class (pytest style)."""

    def test_initialization(self) -> None:
        """Test initialization with valid and invalid configurations."""
        # Test default initialization
        service = MockMentaLLaMA()
        service.initialize({}) 
        assert service.is_healthy()

        # Test initialization with custom mock responses
        custom_responses = {
            "general": {
                "custom": True,
                "model_type": "general"
            }
        }
        service = MockMentaLLaMA()
        service.initialize({"mock_responses": custom_responses})
        assert service.is_healthy()

        # Test shutdown
        service_to_shutdown = MockMentaLLaMA()
        service_to_shutdown.initialize({})
        service_to_shutdown.shutdown()
        assert not service_to_shutdown.is_healthy()

        # Test initialization failure (Example)
        # Note: The mock might not actually throw for invalid config types
        # unless specifically designed to. This is a placeholder test.
        # service = MockMentaLLaMA()
        # with pytest.raises(InvalidConfigurationError):
        #     service.initialize({"mock_responses": "not-a-dict"})

    def test_process_with_invalid_inputs(self) -> None:
        """Test process method with invalid inputs ensuring proper error handling."""
        # Test empty text
        with pytest.raises(InvalidRequestError):
            self.service.process("")

        # Test non-string text
        with pytest.raises(InvalidRequestError):
            self.service.process(123) 

        # Test invalid model type
        with pytest.raises(ModelNotFoundError):
            self.service.process("Some text", "nonexistent_model_type")

        # Test with uninitialized service
        uninitialized_service = MockMentaLLaMA()
        with pytest.raises(ServiceUnavailableError):
            uninitialized_service.process("Some text")

    def test_process_returns_expected_structure(self) -> None:
        """Test that process returns the expected response structure with all required fields."""
        # Test general model (default)
        result = self.service.process(self.sample_text)
        assert isinstance(result, dict)
        assert "model_type" in result
        assert result["model_type"] == "general"
        assert "timestamp" in result
        assert "content" in result

        # Verify timestamp is recent ISO format
        timestamp_str = result["timestamp"]
        timestamp = datetime.fromisoformat(timestamp_str)
        if timestamp.tzinfo is None:
             timestamp = timestamp.replace(tzinfo=UTC)
        assert (datetime.now(UTC) - timestamp).total_seconds() < 10

        # Test all available model types
        for model_type in [
            "depression_detection",
            "risk_assessment",
            "sentiment_analysis",
            "wellness_dimensions",
            "digital_twin",
        ]: 
            result = self.service.process(self.sample_text, model_type)
            assert result["model_type"] == model_type

    def test_detect_depression(self) -> None:
        """Test depression detection functionality ensuring clinical metrics are present."""
        result = self.service.detect_depression(self.sample_text)
        assert "depression_signals" in result
        assert "severity" in result["depression_signals"]
        assert "confidence" in result["depression_signals"]
        assert "key_indicators" in result["depression_signals"]
        assert isinstance(result["depression_signals"]["key_indicators"], list)

        # Verify clinical recommendations
        assert "recommendations" in result
        assert "suggested_assessments" in result["recommendations"]

    def test_assess_risk(self) -> None:
        """Test risk assessment functionality for self-harm detection."""
        # Test without specific risk type
        result = self.service.assess_risk(self.sample_text)
        assert "risk_assessment" in result
        assert "overall_risk_level" in result["risk_assessment"]
        assert "identified_risks" in result["risk_assessment"]

        # Test with specific risk type
        result = self.service.assess_risk(self.sample_text, "self-harm")
        assert "risk_assessment" in result
        # Check that only self-harm risks are included
        if result["risk_assessment"]["identified_risks"]:
            for risk in result["risk_assessment"]["identified_risks"]:
                assert risk["risk_type"] == "self-harm"

        # Verify clinical recommendations exist
        assert "recommendations" in result

    def test_analyze_sentiment(self) -> None:
        """Test sentiment analysis functionality for emotional valence detection."""
        result = self.service.analyze_sentiment(self.sample_text)
        assert "sentiment" in result
        assert "emotions" in result
        assert "overall_score" in result["sentiment"]
        assert "primary_emotions" in result["emotions"]
        assert isinstance(result["emotions"]["primary_emotions"], list)

        # Check emotional insights
        assert "analysis" in result
        assert "emotional_themes" in result["analysis"]

    def test_analyze_wellness_dimensions(self) -> None:
        """Test wellness dimensions analysis functionality with comprehensive measures."""
        # Test without specific dimensions
        result = self.service.analyze_wellness_dimensions(self.sample_text)
        assert "wellness_dimensions" in result
        assert isinstance(result["wellness_dimensions"], list)

        # Test with specific dimensions - corrected function call
        result = self.service.analyze_wellness_dimensions(
            self.sample_text, dimensions=["emotional", "social"]
        )

        # Corrected list comprehension and assertion
        assert "wellness_dimensions" in result
        dimensions = [dim["dimension"] for dim in result["wellness_dimensions"]]
        assert "emotional" in dimensions
        assert "social" in dimensions

        # Ensure analysis and recommendations are provided
        assert "analysis" in result
        assert "recommendations" in result

    def test_digital_twin_session_workflow(self) -> None:
        """Test the complete digital twin session workflow from creation to insights."""
        # Create a digital twin
        # Use consistent text data
        twin_result = self.service.generate_digital_twin(
            text_data=[self.sample_text],
            demographic_data={"age": 35, "gender": "female"},
            medical_history={"conditions": ["anxiety", "insomnia"]},
            treatment_history={"medications": ["escitalopram"]},
        )
        assert "digital_twin_id" in twin_result
        twin_id = twin_result["digital_twin_id"]

        # Create a session with the digital twin
        session_result = self.service.create_digital_twin_session(twin_id, session_type="therapy")
        assert "session_id" in session_result
        session_id = session_result["session_id"]

        # Get session details
        session_details = self.service.get_digital_twin_session(session_id)
        assert session_details["twin_id"] == twin_id
        assert session_details["status"] == "active"

        # Send message to session
        message_result = self.service.send_message_to_session(session_id, "How can I manage my anxiety better?")
        assert "response" in message_result
        assert "messages" in message_result
        assert len(message_result["messages"]) > 0

        # End session
        end_result = self.service.end_digital_twin_session(session_id)
        assert end_result["status"] == "completed"
        assert "summary" in end_result

        # Get session insights
        insights = self.service.get_session_insights(session_id)
        assert "insights" in insights
        assert "themes" in insights["insights"]
        assert "recommendations" in insights["insights"]
