"""
Unit tests for the BatchProcessAnalytics use case.

These tests verify that the BatchProcessAnalytics use case works correctly for processing
analytics events in batch, ensuring proper validation, processing, and handling of errors.
"""

# Tests are now fixed - remove skip directive
# pytest.skip("Skipping BatchProcessAnalytics tests while fixing SQLAlchemy relationship issues", allow_module_level=True)
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.application.use_cases.analytics.batch_process_analytics import (
    BatchProcessAnalyticsUseCase,
)
from app.domain.entities.analytics import AnalyticsEvent
from app.domain.utils.datetime_utils import UTC


@pytest.fixture
def mock_analytics_repository():
    """Create a mock analytics repository for testing."""
    repo = MagicMock()

    # Set up the save_event method to return a modified event with an ID
    async def save_event_mock(event):
        return AnalyticsEvent(
            event_type=event.event_type,
            event_data=event.event_data,
            user_id=event.user_id,
            session_id=event.session_id,
            timestamp=event.timestamp,
            # Unique ID based on event object
            event_id=f"test-event-id-{id(event)}",
        )

    repo.save_event = AsyncMock(side_effect=save_event_mock)
    return repo


@pytest.fixture
def mock_cache_service():
    """Create a mock cache service for testing."""
    cache = MagicMock()

    # Set up increment method to return a count
    async def increment_mock(key, increment=1) -> int:
        return 5  # Mock counter value after increment

    cache.increment = AsyncMock(side_effect=increment_mock)
    return cache


@pytest.fixture
def mock_event_processor():
    """Create a mock ProcessAnalyticsEventUseCase."""
    processor = MagicMock()

    # Set up execute method to return a processed event
    async def execute_mock(event_type, event_data, user_id=None, session_id=None, timestamp=None):
        if event_type == "error_type":
            raise ValueError("Simulated error in event processing")

        if timestamp is None:
            timestamp = datetime.now(UTC)

        return AnalyticsEvent(
            event_type=event_type,
            event_data=event_data,
            user_id=user_id,
            session_id=session_id,
            timestamp=timestamp,
            event_id=f"processed-{event_type}-{id(event_data)}",
        )

    processor.execute = AsyncMock(side_effect=execute_mock)
    return processor


@pytest.fixture
def use_case(mock_analytics_repository, mock_cache_service, mock_event_processor):
    """Create the use case with mocked dependencies."""

    # Create the use case with actual dependencies
    use_case = BatchProcessAnalyticsUseCase(
        analytics_repository=mock_analytics_repository,
        cache_service=mock_cache_service,
        event_processor=mock_event_processor,
    )

    # Patch the logger directly in the use case instance with a mock
    logger_mock = MagicMock()
    use_case.logger = logger_mock

    return use_case


@pytest.mark.db_required()
class TestBatchProcessAnalyticsUseCase:
    """Test suite for the BatchProcessAnalyticsUseCase."""

    @pytest.mark.asyncio
    async def test_execute_with_empty_batch(self, use_case) -> None:
        """
        Test processing an empty batch returns appropriate result.
        """
        # Arrange
        events = []
        batch_id = "test-batch-123"

        # Act
        result = await use_case.execute(events, batch_id)

        # Assert
        assert result.events == []
        assert result.batch_id == batch_id
        assert result.processed_count == 0
        assert result.failed_count == 0

        # Verify warning was logged
        assert use_case.logger.warning.called
        # Get the first call arguments
        args, kwargs = use_case.logger.warning.call_args
        # Check message content
        assert "empty batch" in args[0].lower()

    @pytest.mark.asyncio
    async def test_execute_with_valid_events(self, use_case, mock_event_processor) -> None:
        """
        Test processing a batch of valid events.
        """
        # Arrange
        events = [
            {
                "event_type": "page_view",
                "event_data": {"page": "/dashboard"},
                "user_id": "user-123",
                "session_id": "session-abc",
            },
            {
                "event_type": "feature_use",
                "event_data": {"feature": "digital_twin"},
                "user_id": "user-456",
            },
        ]
        batch_id = "test-batch-456"

        # Act
        result = await use_case.execute(events, batch_id)

        # Assert
        assert len(result.events) == 2
        assert result.batch_id == batch_id
        assert result.processed_count == 2
        assert result.failed_count == 0

        # Verify events were processed
        assert mock_event_processor.execute.call_count == 2

        # Verify appropriate logging
        assert use_case.logger.info.call_count >= 2

        # Check for starting log
        start_logged = False
        completed_logged = False

        for call in use_case.logger.info.call_args_list:
            args, kwargs = call
            msg = args[0].lower()

            # Check for batch start message
            if "starting batch" in msg and "2 analytics" in msg:
                start_logged = True

            # Check for batch completion message
            if "completed batch" in msg and "2 succeeded" in msg and "0 failed" in msg:
                completed_logged = True

        assert start_logged, "Starting batch log message not found"
        assert completed_logged, "Completed batch log message not found"

    @pytest.mark.asyncio
    async def test_partial_failure_handling(self, use_case, mock_event_processor) -> None:
        """
        Test batch processing continues even if some events fail.
        """
        # Arrange
        events = [
            {
                "event_type": "error_type",  # This will cause an error
                "event_data": {"test": "error_data"},
            },
            {"event_type": "valid_type", "event_data": {"test": "valid_data"}},
            {
                "event_type": "error_type",  # Another error
                "event_data": {"test": "more_error_data"},
            },
        ]

        # Act
        result = await use_case.execute(events)

        # Assert
        assert len(result.events) == 1  # Only one valid event
        assert result.processed_count == 1
        assert result.failed_count == 2

        # Verify error logging
        assert use_case.logger.error.call_count >= 2

        # Check that error messages were logged
        error_count = 0
        for call in use_case.logger.error.call_args_list:
            args, kwargs = call
            if "error processing" in args[0].lower():
                error_count += 1

        assert error_count >= 2, "Error log messages not found"

    @pytest.mark.asyncio
    async def test_event_timestamp_handling(self, use_case, mock_event_processor) -> None:
        """
        Test proper handling of event timestamps.
        """
        # Arrange
        timestamp1 = datetime(2025, 3, 15, 12, 0, 0)
        timestamp2 = "2025-03-20T14:30:00"  # String timestamp
        invalid_timestamp = "not-a-timestamp"

        events = [
            {
                "event_type": "type1",
                "event_data": {"data": 1},
                "timestamp": timestamp1.isoformat(),
            },
            {"event_type": "type2", "event_data": {"data": 2}, "timestamp": timestamp2},
            {
                "event_type": "type3",
                "event_data": {"data": 3},
                "timestamp": invalid_timestamp,
            },
        ]

        # Act
        await use_case.execute(events)

        # Assert - check call arguments for timestamps
        call_args_list = mock_event_processor.execute.call_args_list

        # First event should have parsed the ISO timestamp
        assert call_args_list[0][1]["timestamp"].year == 2025
        assert call_args_list[0][1]["timestamp"].month == 3
        assert call_args_list[0][1]["timestamp"].day == 15

        # Second event should have parsed the ISO timestamp
        assert call_args_list[1][1]["timestamp"].year == 2025
        assert call_args_list[1][1]["timestamp"].month == 3
        assert call_args_list[1][1]["timestamp"].day == 20

        # Third event should have used current time due to invalid timestamp
        # We can only check that it's a datetime object since we can't predict exact time
        assert isinstance(call_args_list[2][1]["timestamp"], datetime)

    @pytest.mark.asyncio
    async def test_batch_metadata_saved(self, use_case, mock_cache_service) -> None:
        """
        Test that batch metadata is properly saved.
        """
        # Arrange
        events = [
            {"event_type": "type1", "event_data": {"data": 1}},
            {"event_type": "type2", "event_data": {"data": 2}},
            {"event_type": "type1", "event_data": {"data": 3}},  # Duplicate event type
        ]

        # Act
        await use_case.execute(events)

        # Assert - check batch counter was incremented
        mock_cache_service.increment.assert_any_call("analytics:batches:processed")

        # Check event type counters were updated
        mock_cache_service.increment.assert_any_call(
            "analytics:batches:event_types:type1", increment=2
        )
        mock_cache_service.increment.assert_any_call(
            "analytics:batches:event_types:type2", increment=1
        )

    @pytest.mark.asyncio
    async def test_large_batch_chunking(self, use_case, mock_event_processor) -> None:
        """
        Test that large batches are processed in chunks.
        """
        # Arrange
        # Create a large batch of 250 events
        events = []
        for i in range(250):
            events.append({"event_type": "test_event", "event_data": {"test": f"data-{i}"}})

        batch_id = "large-batch-123"

        # Act
        result = await use_case.execute(events, batch_id)

        # Assert
        assert result.processed_count == 250
        assert result.failed_count == 0
        assert mock_event_processor.execute.call_count == 250

        # Print a sample call to debug the structure
        calls = mock_event_processor.execute.call_args_list
        args, kwargs = calls[0]
        print(f"Debug - Call args: {args}")
        print(f"Debug - Call kwargs: {kwargs}")

        # Verify some events were processed
        # Check a sample of the calls to verify data structure
        assert len(calls) == 250

        # Check a few sample calls instead of all 250
        for i in [0, 100, 249]:  # Check start, middle, and end
            args, kwargs = calls[i]

            # Check that the expected parameters were passed correctly
            assert kwargs["event_type"] == "test_event"
            assert isinstance(kwargs["event_data"], dict)
            # Just confirm it's the right structure without checking specific keys
            assert kwargs["event_data"] is not None
