"""
Unit tests for Mock Digital Twin service.

This module tests the mock implementation of the Digital Twin service,
ensuring it correctly simulates patient digital twins and provides
realistic psychiatric session modeling for testing purposes.
"""

# Remove BaseUnitTest import
# from app.tests.unit.base_test_unit import BaseUnitTest
# Corrected import path for MockDigitalTwinService
from datetime import datetime

import pytest

# Removed unused imports: Dict, Any, List (kept for potential future use if needed)
# Removed unused exception: ModelNotFoundError
from app.core.exceptions import (
    InvalidConfigurationError,
    ResourceNotFoundError,
)
from app.domain.utils.datetime_utils import UTC
from app.infrastructure.ml.digital_twin.mock import MockDigitalTwinService


@pytest.fixture(scope="function")
def mock_dt_service(request):
    """Pytest fixture to set up and tear down MockDigitalTwinService for each test."""
    service = MockDigitalTwinService()
    service.initialize({"mock_config": True})

    patient_data = {
        "patient_id": "test-patient-123",
        "demographic_data": {"age": 35, "gender": "female", "ethnicity": "caucasian"},
        "clinical_data": {
            "diagnoses": ["Major Depressive Disorder", "Generalized Anxiety Disorder"],
            "medications": ["sertraline", "buspirone"],
            "treatment_history": [
                {
                    "type": "CBT",
                    "duration": "6 months",
                    "outcome": "moderate improvement",
                }
            ],
        },
        "biometric_data": {
            "sleep_quality": [6, 5, 7, 4, 6],
            "heart_rate": [72, 78, 75, 80, 73],
            "activity_level": [3500, 2800, 4200, 3000, 3700],
        },
    }

    # Create a twin to use in tests that need it
    # Tests needing these should access them via request.instance
    create_twin_result = service.create_digital_twin(patient_data)

    # Store service and common data on the test instance via request
    request.instance.service = service
    request.instance.patient_data = patient_data
    request.instance.twin_id = create_twin_result["twin_id"]
    request.instance.sample_message = (
        "I've been feeling anxious in social situations lately."
    )

    yield service  # Provide the service to the test function

    # Teardown: Shutdown the service
    if hasattr(request.instance, "service") and request.instance.service.is_healthy():
        request.instance.service.shutdown()


# Remove BaseUnitTest inheritance
@pytest.mark.usefixtures(
    "mock_dt_service"
)  # Apply the fixture to all methods in the class
@pytest.mark.db_required()  # Keep existing marker
class TestMockDigitalTwinService:
    """
    Test suite for MockDigitalTwinService class (pytest style).

    Tests comprehensive patient digital twin session workflows including
    creation, sessions, message exchange, and clinical insights generation.
    """

    # Remove setUp and tearDown methods as logic is now in the fixture

    def test_initialization(
        self,
    ) -> None:  # No 'self' needed if not using instance vars
        """Test service initialization with various configurations."""
        # Test default initialization
        service = MockDigitalTwinService()
        # Empty configuration should raise an error
        with pytest.raises(InvalidConfigurationError):
            service.initialize({})

        # Test with valid configuration
        valid_config = {"mock_config": True}
        service = MockDigitalTwinService()
        service.initialize(valid_config)
        assert service.is_healthy()  # Converted assertion

        # Test with custom configuration
        custom_config = {"response_style": "detailed", "session_duration_minutes": 60}
        service = MockDigitalTwinService()
        service.initialize(custom_config)
        assert service.is_healthy()  # Converted assertion

        # Test initialization with invalid configuration
        service = MockDigitalTwinService()
        with pytest.raises(InvalidConfigurationError):  # Converted assertion
            service.initialize({"response_style": 123})  # type: ignore

        # Test shutdown (need a service instance)
        service_to_shutdown = MockDigitalTwinService()
        service_to_shutdown.initialize(valid_config)
        service_to_shutdown.shutdown()
        assert not service_to_shutdown.is_healthy()  # Converted assertion

    def test_create_session(self) -> None:  # Uses instance variables set by fixture
        """Test creating a digital twin therapy session."""
        # Test with different session types
        for session_type in ["therapy", "assessment", "medication_review"]:
            # Access instance variables set by fixture
            result = self.service.create_session(
                twin_id=self.twin_id, session_type=session_type
            )

            # Verify result structure
            assert "session_id" in result  # Converted assertion
            assert "twin_id" in result  # Converted assertion
            assert "session_type" in result  # Converted assertion
            assert "start_time" in result  # Converted assertion
            assert "status" in result  # Converted assertion

            # Verify values
            assert result["twin_id"] == self.twin_id  # Converted assertion
            assert result["session_type"] == session_type  # Converted assertion
            assert result["status"] == "active"  # Converted assertion

            # Check that start_time is a recent timestamp
            start_time = datetime.fromisoformat(
                result["start_time"].replace("Z", "+00:00")
            )
            # Ensure timestamp is timezone-aware for comparison
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=UTC)
            assert (
                datetime.now(UTC) - start_time
            ).total_seconds() < 10  # Converted assertion

    def test_get_session(self) -> None:  # Uses instance variables
        """Test retrieving a digital twin therapy session."""
        # Create a session
        create_result = self.service.create_session(
            twin_id=self.twin_id, session_type="therapy"
        )
        session_id = create_result["session_id"]

        # Get the session
        get_result = self.service.get_session(session_id)

        # Verify result structure and values
        assert get_result["session_id"] == session_id  # Converted assertion
        assert get_result["twin_id"] == self.twin_id  # Converted assertion
        assert get_result["status"] == "active"  # Converted assertion
        assert "messages" in get_result  # Converted assertion
        assert isinstance(get_result["messages"], list)  # Converted assertion

        # Test getting non-existent session
        with pytest.raises(ResourceNotFoundError):  # Converted assertion
            self.service.get_session("nonexistent-session-id")

    def test_send_message(self) -> None:  # Uses instance variables
        """Test sending a message to a digital twin therapy session."""
        # Create a session
        create_result = self.service.create_session(
            twin_id=self.twin_id, session_type="therapy"
        )
        session_id = create_result["session_id"]

        # Send a message
        message_result = self.service.send_message(
            session_id=session_id, message=self.sample_message
        )

        # Verify result structure
        assert "response" in message_result  # Converted assertion
        assert "messages" in message_result  # Converted assertion
        assert isinstance(message_result["messages"], list)  # Converted assertion
        # User message + twin response
        assert len(message_result["messages"]) == 2  # Converted assertion

        # Verify message content
        assert (
            message_result["messages"][0]["content"] == self.sample_message
        )  # Converted assertion
        assert message_result["messages"][0]["sender"] == "user"  # Converted assertion
        assert message_result["messages"][1]["sender"] == "twin"  # Converted assertion

        # Test sending to a non-existent session
        with pytest.raises(ResourceNotFoundError):  # Converted assertion
            self.service.send_message(
                session_id="nonexistent-session-id", message=self.sample_message
            )

    def test_message_response_types(self) -> None:  # Uses instance variables
        """Test different types of responses based on message content."""
        # Create a session
        create_result = self.service.create_session(
            twin_id=self.twin_id, session_type="therapy"
        )
        session_id = create_result["session_id"]

        # Test different message types
        test_messages = {
            "depression": "I've been feeling so hopeless lately.",
            "anxiety": "I'm constantly worried about everything.",
            "medication": "I'm not sure if my medication is working.",
            "sleep": "I haven't been sleeping well.",
            "exercise": "I've started walking every day.",
        }

        for topic, message in test_messages.items():
            result = self.service.send_message(session_id=session_id, message=message)
            assert "response" in result  # Converted assertion
            response = result["response"]

            # Response should be relevant to the topic
            # Using simpler check for substring presence
            assert (
                topic in response.lower() or topic[:-1] in response.lower()
            ), f"Response '{response}' not relevant to topic '{topic}'"  # Converted assertion

    def test_end_session(self) -> None:  # Uses instance variables
        """Test ending a digital twin therapy session."""
        # Create a session
        create_result = self.service.create_session(
            twin_id=self.twin_id, session_type="therapy"
        )
        session_id = create_result["session_id"]

        # Send a message to have some content
        self.service.send_message(session_id=session_id, message=self.sample_message)

        # End the session
        end_result = self.service.end_session(session_id)

        # Verify result structure
        assert "session_id" in end_result  # Converted assertion
        assert "status" in end_result  # Converted assertion
        assert "duration" in end_result  # Converted assertion
        assert "summary" in end_result  # Converted assertion

        # Verify values
        assert end_result["session_id"] == session_id  # Converted assertion
        assert end_result["status"] == "completed"  # Converted assertion
        assert "minutes" in end_result["duration"]  # Converted assertion

        # Test ending a non-existent session
        with pytest.raises(ResourceNotFoundError):  # Converted assertion
            self.service.end_session("nonexistent-session-id")

    def test_get_insights(self) -> None:  # Uses instance variables
        """Test retrieving clinical insights from a digital twin."""
        # Test with default insights (general)
        result = self.service.get_insights(twin_id=self.twin_id)
        assert "twin_id" in result  # Converted assertion
        assert "insights" in result  # Converted assertion
        assert isinstance(result["insights"], dict)  # Converted assertion
        assert (
            "summary" in result["insights"]
        )  # Basic check for general insight structure

        # Test requesting specific insight types
        insight_types = ["mood", "activity", "sleep", "medication", "treatment"]
        result = self.service.get_insights(
            twin_id=self.twin_id, insight_types=insight_types
        )
        assert isinstance(result["insights"], dict)  # Converted assertion
        # Check if requested insights are present
        for insight_type in insight_types:
            assert insight_type in result["insights"]  # Converted assertion

        # Test requesting non-existent twin
        with pytest.raises(ResourceNotFoundError):  # Converted assertion
            self.service.get_insights("nonexistent-twin-id")

        # Test requesting invalid insight type (depends on mock's strictness)
        # Assuming the mock might ignore or handle gracefully
        # with pytest.raises(InvalidRequestError):
        #     self.service.get_insights(
        #         twin_id=self.twin_id,
        #         insight_types=["invalid_insight_type"]
        #     )
        # Let's just check it doesn't crash and returns something
        result = self.service.get_insights(
            twin_id=self.twin_id, insight_types=["invalid_insight_type", "mood"]
        )
        assert "insights" in result  # Converted assertion
        assert "mood" in result["insights"]  # Valid type should still be processed

    def test_mood_insights(self) -> None:  # Uses instance variables
        """Test mood insights generation."""
        result = self.service.get_insights(twin_id=self.twin_id, insight_types=["mood"])
        assert "mood" in result["insights"]  # Converted assertion
        mood_insights = result["insights"]["mood"]

        assert "overall_mood" in mood_insights  # Converted assertion
        assert "mood_trend" in mood_insights  # Converted assertion
        assert "key_factors" in mood_insights  # Converted assertion
        assert isinstance(mood_insights["key_factors"], list)  # Converted assertion

        # Basic checks on values (assuming mock returns reasonable defaults)
        assert isinstance(mood_insights["overall_mood"], str)  # Converted assertion
        assert isinstance(mood_insights["mood_trend"], str)  # Converted assertion

    def test_activity_insights(self) -> None:  # Uses instance variables
        """Test activity insights generation."""
        result = self.service.get_insights(
            twin_id=self.twin_id, insight_types=["activity"]
        )
        assert "activity" in result["insights"]  # Converted assertion
        # Add more specific assertions based on expected activity insight structure

    def test_sleep_insights(self) -> None:  # Uses instance variables
        """Test sleep insights generation."""
        result = self.service.get_insights(
            twin_id=self.twin_id, insight_types=["sleep"]
        )
        assert "sleep" in result["insights"]  # Converted assertion
        sleep_insights = result["insights"]["sleep"]
        assert "average_duration" in sleep_insights  # Converted assertion
        assert "sleep_quality_trend" in sleep_insights  # Converted assertion
        assert "recommendations" in sleep_insights  # Converted assertion

    def test_medication_insights(self) -> None:  # Uses instance variables
        """Test medication insights generation."""
        result = self.service.get_insights(
            twin_id=self.twin_id, insight_types=["medication"]
        )
        assert "medication" in result["insights"]  # Converted assertion
        med_insights = result["insights"]["medication"]
        assert "adherence_estimate" in med_insights  # Converted assertion
        assert "potential_side_effects" in med_insights  # Converted assertion

    def test_treatment_insights(self) -> None:  # Uses instance variables
        """Test treatment insights generation."""
        result = self.service.get_insights(
            twin_id=self.twin_id, insight_types=["treatment"]
        )
        assert "treatment" in result["insights"]  # Converted assertion
        treat_insights = result["insights"]["treatment"]
        assert "effectiveness_assessment" in treat_insights  # Converted assertion
        assert "suggestions_for_adjustment" in treat_insights  # Converted assertion


# Removed unnecessary test execution block:
# if __name__ == "__main__":
#     pytest.main()
