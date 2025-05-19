"""
Unit tests for ML mock services.

This module tests the mock implementations in app.core.services.ml.mock,
ensuring they correctly implement their respective interfaces and
provide consistent behavior for testing purposes.
"""

from datetime import datetime

import pytest

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError,
)
from app.domain.utils.datetime_utils import UTC

# Corrected imports from infrastructure layer
from app.infrastructure.ml.mentallama.mock import MockMentaLLaMA
from app.infrastructure.ml.phi.mock import MockPHIDetection

# Apply test markers for categorization
pytestmark = [pytest.mark.unit, pytest.mark.ml]


@pytest.mark.db_required
class TestMockMentaLLaMA:
    """Test suite for MockMentaLLaMA class."""

    @pytest.fixture
    def mock_service(self) -> MockMentaLLaMA:
        """Create and initialize a MockMentaLLaMA instance."""
        service = MockMentaLLaMA()
        service.initialize({})
        return service

    @pytest.fixture
    def sample_text(self) -> str:
        """Create sample text for testing."""
        return (
            "I've been feeling down for several weeks. I'm constantly tired, "
            "have trouble sleeping, and don't enjoy things anymore. Sometimes "
            "I wonder if life is worth living, but I wouldn't actually hurt myself."
        )

    def test_initialization(self):
        """Test initialization with valid and invalid configurations."""
        # Test default initialization
        service = MockMentaLLaMA()
        service.initialize({})
        assert service.is_healthy()

        # Test initialization with custom mock responses
        custom_responses = {"general": {"custom": True, "model_type": "general"}}
        service = MockMentaLLaMA()
        service.initialize({"mock_responses": custom_responses})
        assert service.is_healthy()

        # Test shutdown
        service.shutdown()
        assert not service.is_healthy()

        # Test initialization failure
        service = MockMentaLLaMA()
        with pytest.raises(InvalidConfigurationError):
            # Pass invalid config that would cause error during processing
            service.initialize({"mock_responses": "not-a-dict"})

    def test_process_with_invalid_inputs(self, mock_service):
        """Test process method with invalid inputs."""
        # Test empty text
        with pytest.raises(InvalidRequestError):
            mock_service.process("")

        # Test non-string text
        with pytest.raises(InvalidRequestError):
            mock_service.process(123)

        # Test invalid model type
        with pytest.raises(ModelNotFoundError):
            mock_service.process("Some text", "nonexistent_model_type")

        # Test with uninitialized service
        uninitialized_service = MockMentaLLaMA()
        with pytest.raises(ServiceUnavailableError):
            uninitialized_service.process("Some text")

    def test_process_returns_expected_structure(self, mock_service, sample_text):
        """Test that process returns the expected response structure."""
        # Test general model (default)
        result = mock_service.process(sample_text)
        assert isinstance(result, dict)
        assert "model_type" in result
        assert result["model_type"] == "general"
        assert "timestamp" in result
        assert "content" in result
        # Verify timestamp is recent ISO format
        timestamp = datetime.fromisoformat(result["timestamp"].rstrip("Z"))
        # Use timezone-aware comparison to prevent TypeError
        assert (datetime.now(UTC) - timestamp).total_seconds() < 10

        # Test all available model types
        model_types_to_test = [
            "depression_detection",
            "risk_assessment",
            "sentiment_analysis",
            "wellness_dimensions",
            "digital_twin",
        ]
        for model_type in model_types_to_test:
            result = mock_service.process(sample_text, model_type)
            assert result["model_type"] == model_type

    def test_detect_depression(self, mock_service, sample_text):
        """Test depression detection functionality."""
        result = mock_service.detect_depression(sample_text)
        assert "depression_signals" in result
        assert "severity" in result["depression_signals"]
        assert "confidence" in result["depression_signals"]
        assert "key_indicators" in result["depression_signals"]
        assert isinstance(result["depression_signals"]["key_indicators"], list)

    def test_assess_risk(self, mock_service, sample_text):
        """Test risk assessment functionality."""
        # Test without specific risk type
        result = mock_service.assess_risk(sample_text)
        assert "risk_assessment" in result
        assert "overall_risk_level" in result["risk_assessment"]
        assert "identified_risks" in result["risk_assessment"]

        # Test with specific risk type
        result = mock_service.assess_risk(sample_text, "self-harm")
        assert "risk_assessment" in result
        # Check that only self-harm risks are included
        for risk in result["risk_assessment"]["identified_risks"]:
            assert risk["risk_type"] == "self-harm"

    def test_analyze_sentiment(self, mock_service, sample_text):
        """Test sentiment analysis functionality."""
        result = mock_service.analyze_sentiment(sample_text)
        assert "sentiment" in result
        assert "emotions" in result
        assert "overall_score" in result["sentiment"]
        assert "primary_emotions" in result["emotions"]
        assert isinstance(result["emotions"]["primary_emotions"], list)

    def test_analyze_wellness_dimensions(self, mock_service, sample_text):
        """Test wellness dimensions analysis functionality."""
        # Test without specific dimensions
        result = mock_service.analyze_wellness_dimensions(sample_text)
        assert "wellness_dimensions" in result
        assert isinstance(result["wellness_dimensions"], list)

        # Test with specific dimensions
        result = mock_service.analyze_wellness_dimensions(
            sample_text, dimensions=["emotional", "social"]
        )
        assert "wellness_dimensions" in result
        # Correct list comprehension
        dimensions_found = [dim["dimension"] for dim in result["wellness_dimensions"]]
        assert "emotional" in dimensions_found
        assert "social" in dimensions_found
        assert len(dimensions_found) == 2  # Ensure only requested dimensions are returned

    def test_digital_twin_session_workflow(self, mock_service, sample_text):
        """Test the digital twin session workflow."""
        # Create a digital twin
        twin_result = mock_service.generate_digital_twin(
            text_data=[sample_text],
            demographic_data={"age": 35, "gender": "female"},
            medical_history={"conditions": ["anxiety", "insomnia"]},
            treatment_history={"medications": ["escitalopram"]},
        )
        assert "digital_twin_id" in twin_result
        twin_id = twin_result["digital_twin_id"]

        # Create a session with the digital twin
        session_result = mock_service.create_digital_twin_session(twin_id, session_type="therapy")
        assert "session_id" in session_result
        session_id = session_result["session_id"]

        # Get session details
        session_details = mock_service.get_digital_twin_session(session_id)
        assert session_details["twin_id"] == twin_id
        assert session_details["status"] == "active"

        # Send message to session
        message_result = mock_service.send_message_to_session(
            session_id, "How can I manage my anxiety better?"
        )
        assert "response" in message_result
        assert "messages" in message_result
        assert len(message_result["messages"]) > 0

        # End session
        end_result = mock_service.end_digital_twin_session(session_id)
        assert end_result["status"] == "completed"
        assert "summary" in end_result

        # Get session insights
        insights = mock_service.get_session_insights(session_id)
        assert "insights" in insights
        assert "themes" in insights["insights"]
        assert "recommendations" in insights["insights"]


class TestMockPHIDetection:
    """Test suite for MockPHIDetection class."""

    # Apply PHI-specific marker for these tests
    pytestmark = [pytest.mark.phi]

    @pytest.fixture
    def mock_phi_service(self) -> MockPHIDetection:
        """Create and initialize a MockPHIDetection instance."""
        service = MockPHIDetection()
        service.initialize({})
        return service

    @pytest.fixture
    def sample_phi_text(self) -> str:
        """Create sample text with mock PHI for testing."""
        return (
            "Patient John Smith (SSN: 123-45-6789) was admitted on 03/15/2024. "
            "His email is john.smith@example.com and phone number is (555) 123-4567. "
            "He resides at 123 Main Street, Springfield, IL 62701."
        )

    def test_initialization(self):
        """Test initialization with valid and invalid configurations."""
        # Test default initialization
        service = MockPHIDetection()
        service.initialize({})
        assert service.is_healthy()

        # Test shutdown
        service.shutdown()
        assert not service.is_healthy()

        # Test initialization with custom configuration
        service = MockPHIDetection()
        service.initialize({"detection_level": "aggressive"})
        assert service.is_healthy()

    def test_detect_phi_valid_inputs(self, mock_phi_service, sample_phi_text):
        """Test PHI detection with valid inputs."""
        # Test with default parameters
        result = mock_phi_service.detect_phi(sample_phi_text)
        assert "phi_instances" in result
        assert isinstance(result["phi_instances"], list)
        assert len(result["phi_instances"]) > 0
        assert "type" in result["phi_instances"][0]
        assert "text" in result["phi_instances"][0]
        assert "position" in result["phi_instances"][0]
        assert "confidence" in result["phi_instances"][0]

        # Test with specific detection_level parameter
        for level in ["minimal", "moderate", "aggressive"]:
            result = mock_phi_service.detect_phi(sample_phi_text, detection_level=level)
            assert "phi_instances" in result
            assert "detection_level" in result
            assert result["detection_level"] == level

    def test_detect_phi_invalid_inputs(self, mock_phi_service):
        """Test PHI detection with invalid inputs."""
        # Test empty text
        with pytest.raises(InvalidRequestError):
            mock_phi_service.detect_phi("")

        # Test non-string text
        with pytest.raises(InvalidRequestError):
            mock_phi_service.detect_phi(123)

        # Test with uninitialized service
        uninitialized_service = MockPHIDetection()
        with pytest.raises(ServiceUnavailableError):
            uninitialized_service.detect_phi("Some text")

        # Test with invalid detection level
        with pytest.raises(InvalidRequestError):
            mock_phi_service.detect_phi("Some text", detection_level="invalid_level")

    def test_redact_phi(self, mock_phi_service, sample_phi_text):
        """Test PHI redaction functionality."""
        # Test with default parameters
        result = mock_phi_service.redact_phi(sample_phi_text)
        assert "redacted_text" in result
        assert "phi_instances" in result
        assert isinstance(result["phi_instances"], list)

        # Verify that PHI is actually redacted in the text
        redacted_text = result["redacted_text"]
        assert "123-45-6789" not in redacted_text
        assert "[REDACTED]" in redacted_text

        # Test with custom redaction marker
        result = mock_phi_service.redact_phi(sample_phi_text, redaction_marker="[PHI]")
        assert "[PHI]" in result["redacted_text"]

        # Test with specific detection level
        result = mock_phi_service.redact_phi(sample_phi_text, detection_level="aggressive")
        assert "detection_level" in result
        assert result["detection_level"] == "aggressive"

    def test_phi_instance_creation(self, mock_phi_service):
        """Test internal _create_mock_phi_instances method."""
        # Access the protected method directly for testing
        minimal_instances = mock_phi_service._create_mock_phi_instances("minimal")
        moderate_instances = mock_phi_service._create_mock_phi_instances("moderate")
        aggressive_instances = mock_phi_service._create_mock_phi_instances("aggressive")

        # Check that each level produces expected number of instances
        assert len(minimal_instances) <= len(moderate_instances)
        assert len(moderate_instances) <= len(aggressive_instances)

        # Check structure of instances
        for instance in minimal_instances:
            assert "type" in instance
            assert "text" in instance
            assert "position" in instance
            assert "confidence" in instance
