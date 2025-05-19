"""
Unit tests for Mock Digital Twin Service.

This module tests the mock implementation of the Digital Twin service
to ensure it correctly simulates patient interaction and provides consistent
responses for testing purposes.
"""

import re
import uuid

import pytest

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ResourceNotFoundError,
    ServiceUnavailableError,
)
from app.infrastructure.ml.digital_twin.mock import (
    MockDigitalTwinService,
)  # Corrected import path

# Import the correct interface


@pytest.mark.unit()
class TestMockDigitalTwinService:
    """Test suite for MockDigitalTwinService class."""

    @pytest.fixture
    def service(self) -> MockDigitalTwinService:
        """Fixture to provide an instance of the MockDigitalTwinService."""
        return MockDigitalTwinService()

    @pytest.fixture
    def mock_service(self) -> MockDigitalTwinService:
        """Create and initialize a MockDigitalTwinService instance."""
        service = MockDigitalTwinService()
        service.initialize({"mock_config": True})
        return service

    @pytest.fixture
    def sample_patient_id(self) -> str:
        """Create a sample patient ID for testing."""
        return f"test-patient-{uuid.uuid4()}"

    def test_initialization(self):
        """Test initialization with valid and invalid configurations."""
        # Test default initialization
        service = MockDigitalTwinService()
        service.initialize({"mock_config": True})
        assert service.is_healthy()

        # Test shutdown
        service.shutdown()
        # The service should now report as not healthy
        assert not service.is_healthy()

        # Test initialization with empty config
        service = MockDigitalTwinService()
        with pytest.raises(InvalidConfigurationError):
            service.initialize({})

        # Test initialization with invalid config
        service = MockDigitalTwinService()
        with pytest.raises(InvalidConfigurationError):
            service.initialize("not-a-dict")

    def test_create_session(self, mock_service, sample_patient_id):
        """Test creating a new Digital Twin session."""
        # Test with minimal parameters
        result = mock_service.create_session(sample_patient_id)
        assert "session_id" in result
        assert result["patient_id"] == sample_patient_id
        assert "created_at" in result
        assert "expires_at" in result
        assert "processing_time" in result
        assert "metadata" in result
        assert result["metadata"]["mock"] is True

        # Test with additional context
        context = {"demographic": {"age": 35, "gender": "female"}}
        result = mock_service.create_session(sample_patient_id, context=context)
        assert "session_id" in result

        # Test with uninitialized service
        uninitialized_service = MockDigitalTwinService()
        with pytest.raises(ServiceUnavailableError):
            uninitialized_service.create_session(sample_patient_id)

    def test_get_session(self, mock_service, sample_patient_id):
        """Test retrieving a Digital Twin session."""
        # Create a session first
        create_result = mock_service.create_session(sample_patient_id)
        session_id = create_result["session_id"]

        # Get the session
        result = mock_service.get_session(session_id)
        assert result["session_id"] == session_id
        assert result["patient_id"] == sample_patient_id
        assert "created_at" in result
        assert "expires_at" in result
        assert "history" in result
        assert "context" in result
        assert "metadata" in result

        # Test getting a non-existent session
        non_existent_id = str(uuid.uuid4())
        with pytest.raises(ResourceNotFoundError):
            mock_service.get_session(non_existent_id)

        # Test with uninitialized service
        uninitialized_service = MockDigitalTwinService()
        with pytest.raises(ServiceUnavailableError):
            uninitialized_service.get_session(session_id)

    def test_send_message(self, mock_service, sample_patient_id):
        """Test sending messages to a Digital Twin session."""
        # Create a session first
        create_result = mock_service.create_session(sample_patient_id)
        session_id = create_result["session_id"]

        # Test sending a greeting message
        message = "Hello, how are you?"
        result = mock_service.send_message(session_id, message)
        assert result["session_id"] == session_id
        assert result["patient_id"] == sample_patient_id
        assert result["message"] == message
        assert "response" in result
        assert len(result["response"]) > 0
        assert "timestamp" in result
        assert "processing_time" in result
        assert "metadata" in result

        # Get session to check history
        session = mock_service.get_session(session_id)
        assert len(session["history"]) == 2  # User message and response

        # Test sending a medication-related message
        message = "I have a question about my medication"
        result = mock_service.send_message(session_id, message)
        assert "medication" in result["response"].lower()

        # Test sending a symptom-related message
        message = "I'm feeling very anxious today"
        result = mock_service.send_message(session_id, message)
        assert result["response"] is not None

        # Test sending to a non-existent session
        non_existent_id = str(uuid.uuid4())
        with pytest.raises(ResourceNotFoundError):
            mock_service.send_message(non_existent_id, "Test message")

        # Test with uninitialized service
        uninitialized_service = MockDigitalTwinService()
        with pytest.raises(ServiceUnavailableError):
            uninitialized_service.send_message(session_id, "Test message")

    def test_message_response_types(self, mock_service, sample_patient_id):
        """Test different types of message responses."""
        # Create a session
        create_result = mock_service.create_session(sample_patient_id)
        session_id = create_result["session_id"]

        # Test greeting messages
        for greeting in ["hello", "hi", "hey", "greetings"]:
            result = mock_service.send_message(session_id, greeting)
            assert "hello" in result["response"].lower()

        # Test "how are you" message
        result = mock_service.send_message(session_id, "How are you?")
        assert "how are you feeling" in result["response"].lower()

        # Test medication questions
        for med_term in ["medication", "meds", "pills", "prescription"]:
            result = mock_service.send_message(
                session_id, f"Question about my {med_term}"
            )
            assert "medication" in result["response"].lower()

        # Test appointment questions
        for appt_term in ["appointment", "schedule", "visit", "doctor"]:
            result = mock_service.send_message(session_id, f"Need to {appt_term}")
            assert "appointment" in result["response"].lower()
            assert re.search(
                r"\b[A-Z][a-z]+day, [A-Z][a-z]+ \d+\b", result["response"]
            )  # Date format

        # Test symptom questions
        for symptom_term in ["symptom", "feeling", "pain", "hurt", "sick"]:
            result = mock_service.send_message(session_id, f"I'm {symptom_term}")
            assert (
                "symptom" in result["response"].lower()
                or "feeling" in result["response"].lower()
            )

        # Test wellness questions
        for wellness_term in ["wellness", "exercise", "diet", "sleep", "stress"]:
            result = mock_service.send_message(session_id, f"About my {wellness_term}")
            assert (
                "wellness" in result["response"].lower()
                or "sleep" in result["response"].lower()
            )

        # Test therapy questions
        for therapy_term in ["therapy", "therapist", "counseling", "counselor"]:
            result = mock_service.send_message(session_id, f"My {therapy_term}")
            assert "therapy" in result["response"].lower()

    def test_end_session(self, mock_service, sample_patient_id):
        """Test ending a Digital Twin session."""
        # Create a session first
        create_result = mock_service.create_session(sample_patient_id)
        session_id = create_result["session_id"]

        # End the session
        result = mock_service.end_session(session_id)
        assert result["session_id"] == session_id
        assert result["patient_id"] == sample_patient_id
        assert "ended_at" in result
        assert result["metadata"]["status"] == "ended"

        # Verify session can't be ended again
        with pytest.raises(InvalidRequestError):
            mock_service.end_session(session_id)

        # Test ending a non-existent session
        non_existent_id = str(uuid.uuid4())
        with pytest.raises(ResourceNotFoundError):
            mock_service.end_session(non_existent_id)

        # Test with uninitialized service
        uninitialized_service = MockDigitalTwinService()
        with pytest.raises(ServiceUnavailableError):
            uninitialized_service.end_session(session_id)

    def test_get_insights(self, mock_service, sample_patient_id):
        """Test getting Digital Twin insights."""
        # Test with default parameters
        result = mock_service.get_insights(sample_patient_id)
        assert result["patient_id"] == sample_patient_id
        assert result["insight_type"] == "all"
        assert result["time_period"] == "last_30_days"
        assert "generated_at" in result
        assert "insights" in result
        assert "processing_time" in result
        assert "metadata" in result

        # Verify structure of all insights
        insights = result["insights"]
        assert "mood" in insights
        assert "activity" in insights
        assert "sleep" in insights
        assert "medication" in insights
        assert "treatment" in insights
        assert "summary" in insights
        assert "overall_status" in insights["summary"]
        assert "key_observations" in insights["summary"]
        assert "recommendations" in insights["summary"]

        # Test specific insight types
        for insight_type in ["mood", "activity", "sleep", "medication", "treatment"]:
            result = mock_service.get_insights(
                sample_patient_id, insight_type=insight_type
            )
            assert result["insight_type"] == insight_type
            assert "data" in result["insights"]

        # Test different time periods
        result = mock_service.get_insights(sample_patient_id, time_period="last_7_days")
        assert result["time_period"] == "last_7_days"

        # Test with uninitialized service
        uninitialized_service = MockDigitalTwinService()
        with pytest.raises(ServiceUnavailableError):
            uninitialized_service.get_insights(sample_patient_id)

    def test_mood_insights(self, mock_service, sample_patient_id):
        """Test mood insights specifically."""
        result = mock_service.get_insights(sample_patient_id, insight_type="mood")
        assert result["insights"]["type"] == "mood"
        mood_data = result["insights"]["data"]

        # Verify structure within the 'data' dict
        assert "daily_values" in mood_data
        assert "average" in mood_data
        assert "trend" in mood_data
        assert "observations" in mood_data
        assert len(mood_data["daily_values"]) > 0

    def test_activity_insights(self, mock_service, sample_patient_id):
        """Test activity insights specifically."""
        result = mock_service.get_insights(sample_patient_id, insight_type="activity")
        assert result["insights"]["type"] == "activity"
        activity_data = result["insights"]["data"]

        # Verify structure within the 'data' dict
        assert "daily_values" in activity_data
        assert "average" in activity_data
        assert "trend" in activity_data
        assert "observations" in activity_data
        assert len(activity_data["daily_values"]) > 0

    def test_sleep_insights(self, mock_service, sample_patient_id):
        """Test sleep insights specifically."""
        result = mock_service.get_insights(sample_patient_id, insight_type="sleep")
        assert result["insights"]["type"] == "sleep"
        sleep_data = result["insights"]["data"]

        # Verify structure within the 'data' dict
        assert "daily_values" in sleep_data
        assert "average_hours" in sleep_data
        assert "average_quality" in sleep_data
        assert "trend" in sleep_data
        assert "observations" in sleep_data
        assert len(sleep_data["daily_values"]) > 0

    def test_medication_insights(self, mock_service, sample_patient_id):
        """Test medication insights specifically."""
        result = mock_service.get_insights(sample_patient_id, insight_type="medication")
        assert result["insights"]["type"] == "medication"
        med_data = result["insights"]["data"]

        # Verify structure within the 'data' dict
        assert "daily_values" in med_data
        assert "adherence_rate" in med_data
        assert "adherence_label" in med_data
        assert "trend" in med_data
        assert "observations" in med_data
        assert len(med_data["daily_values"]) > 0

    def test_treatment_insights(self, mock_service, sample_patient_id):
        """Test treatment insights specifically."""
        result = mock_service.get_insights(sample_patient_id, insight_type="treatment")
        assert result["insights"]["type"] == "treatment"
        treatment_data = result["insights"]["data"]

        # Verify structure within the 'data' dict
        assert "engagement_score" in treatment_data
        assert "engagement_label" in treatment_data
        assert "appointments" in treatment_data
        assert "completed_tasks" in treatment_data
        assert "upcoming_tasks" in treatment_data
        assert "observations" in treatment_data
        assert len(treatment_data["appointments"]) >= 0
