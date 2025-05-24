"""
Unit tests for the ProcessAnalyticsEvent use case.

These tests verify that the ProcessAnalyticsEvent use case works correctly for processing
individual analytics events and validating them.
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

# Tests are now fixed - remove skip directive
# pytest.skip("Skipping ProcessAnalyticsEvent tests while fixing SQLAlchemy relationship issues", allow_module_level=True)
from app.application.use_cases.analytics.process_analytics_event import (
    ProcessAnalyticsEventUseCase,
)
from app.domain.entities.analytics import AnalyticsEvent
from app.domain.utils.datetime_utils import UTC


@pytest.fixture
def mock_analytics_repository():
    """Create a mock analytics repository."""
    repo = MagicMock()

    # Set up save_event to return an event with ID
    async def save_event_mock(event):
        return AnalyticsEvent(
            event_id="test-event-123",
            event_type=event.event_type,
            event_data=event.event_data,
            user_id=event.user_id,
            session_id=event.session_id,
            timestamp=event.timestamp or datetime.now(UTC),
        )

    repo.save_event = AsyncMock(side_effect=save_event_mock)
    return repo


@pytest.fixture
def mock_cache_service():
    """Create a mock cache service."""
    cache = MagicMock()

    # Set up increment method
    async def increment_mock(key, increment=1) -> int:
        return 5  # Mock counter value

    cache.increment = AsyncMock(side_effect=increment_mock)
    return cache


@pytest.fixture
def mock_phi_detector():
    """Create a mock PHI detector."""
    detector = MagicMock()

    # Default to no PHI detected
    detector.detect_phi.return_value = []

    # Specific behavior for known PHI patterns
    def detect_mock(data):
        if isinstance(data, dict) and "SSN" in str(data):
            return [{"field": "some_field", "type": "SSN"}]
        return []

    detector.detect_phi.side_effect = detect_mock
    return detector


@pytest.fixture
def use_case(mock_analytics_repository, mock_cache_service):
    """Create the use case with mocked dependencies."""

    # Create the use case with dependencies
    use_case = ProcessAnalyticsEventUseCase(
        analytics_repository=mock_analytics_repository, cache_service=mock_cache_service
    )

    # Patch the logger directly in the use case instance with a mock
    logger_mock = MagicMock()
    use_case.logger = logger_mock

    return use_case


# @pytest.mark.db_required() # Decorator might be unnecessary/incorrect here
class TestProcessAnalyticsEventUseCase:
    """Test suite for the ProcessAnalyticsEventUseCase."""

    @pytest.mark.asyncio
    async def test_execute_with_all_parameters(self, use_case, mock_analytics_repository) -> None:
        """
        Test processing an analytics event with all parameters provided.
        """
        # Arrange
        event_type = "page_view"
        event_data = {"page": "/dashboard", "duration": 15}
        user_id = "user-123"
        session_id = "session-456"
        timestamp = datetime.now(UTC)

        # Act
        result = await use_case.execute(
            event_type=event_type,
            event_data=event_data,
            user_id=user_id,
            session_id=session_id,
            timestamp=timestamp,
        )

        # Assert
        assert result.event_type == event_type
        assert result.event_data == event_data
        assert result.user_id == user_id
        assert result.session_id == session_id
        assert result.timestamp == timestamp
        assert result.event_id == "test-event-123"

        # Verify repository was called correctly
        mock_analytics_repository.save_event.assert_called_once()

        # Verify logger was called
        assert use_case.logger.info.called
        # Get the first call arguments
        args, kwargs = use_case.logger.info.call_args
        # Check that the message contains the event type
        assert event_type in args[0]
        # Check that session ID is in kwargs if using extra param
        if kwargs:
            assert kwargs.get("session_id") == session_id

    @pytest.mark.asyncio
    async def test_execute_with_minimal_parameters(self, use_case, mock_analytics_repository) -> None:
        """
        Test processing an analytics event with only required parameters.
        """
        # Arrange
        event_type = "feature_usage"
        event_data = {"feature": "report_generation"}

        # Act
        result = await use_case.execute(event_type=event_type, event_data=event_data)

        # Assert
        assert result.event_type == event_type
        assert result.event_data == event_data
        assert result.user_id is None
        assert result.session_id is None
        assert isinstance(result.timestamp, datetime)
        assert result.event_id == "test-event-123"

        # Verify appropriate logging (without PHI)
        assert use_case.logger.info.called
        # Get the first call arguments
        args, kwargs = use_case.logger.info.call_args
        # Check that the message contains the event type
        assert event_type in args[0]

    @pytest.mark.asyncio
    async def test_real_time_counter_updates(self, use_case, mock_cache_service) -> None:
        """
        Test that real-time counters are updated in cache.
        """
        # Arrange
        event_type = "patient_search"
        event_data = {"query_type": "name"}
        user_id = "provider-789"

        # Act
        await use_case.execute(event_type=event_type, event_data=event_data, user_id=user_id)

        # Assert - verify cache service was called to update counters
        mock_cache_service.increment.assert_any_call(f"analytics:counter:{event_type}")
        mock_cache_service.increment.assert_any_call(f"analytics:user:{user_id}:{event_type}")

    @pytest.mark.asyncio
    async def test_phi_not_logged(self, use_case, mock_analytics_repository, capsys) -> None:
        """
        Test that PHI is not logged in analytics events.
        """
        # Arrange - Create an event with potential PHI in the data
        event_type = "patient_record_view"
        event_data = {
            "patient_id": "p123",
            "record_type": "medical_history",
            "PHI": {
                "name": "John Doe",
                "ssn": "123-45-6789",  # This is PHI and should not be logged
                "address": "123 Main St",
            },
        }
        session_id = "session-xyz"

        # Act
        await use_case.execute(
            event_type=event_type, event_data=event_data, session_id=session_id
        )

        # Assert - Should log the event type but not the PHI
        # Verify through logger mock
        assert use_case.logger.info.called

        # Get log call arguments
        args, _ = use_case.logger.info.call_args
        log_message = args[0]

        # Check that event type is logged
        assert event_type in log_message

        # Check that PHI is not in logs
        assert "123-45-6789" not in log_message  # SSN should not be logged
        assert "John Doe" not in log_message  # Name should not be logged

    @pytest.mark.asyncio
    async def test_repository_error_handling(self, use_case, mock_analytics_repository) -> None:
        """
        Test proper error handling when repository operations fail.
        """
        # Arrange
        mock_analytics_repository.save_event.side_effect = Exception("Database connection error")

        # Act & Assert
        with pytest.raises(Exception) as excinfo:
            await use_case.execute(event_type="error_event", event_data={"test": True})

        assert "Database connection error" in str(excinfo.value)
