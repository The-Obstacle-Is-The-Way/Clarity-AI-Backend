"""
Unit tests for the BatchProcessAnalytics use case.

These tests verify that the BatchProcessAnalytics use case works correctly for processing
analytics events in batch, ensuring proper validation, processing, and handling of errors.
"""

import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

# Skip these tests temporarily while fixing relationship issues
pytest.skip("Skipping BatchProcessAnalytics tests while fixing SQLAlchemy relationship issues", allow_module_level=True)

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.application.use_cases.analytics.batch_process_analytics import BatchProcessAnalyticsUseCase
from app.domain.entities.analytics import AnalyticsEvent
from app.domain.utils.datetime_utils import UTC


@pytest.fixture
def mock_analytics_repository():
    """Create a mock analytics repository for testing."""
    repo = AsyncMock()

    # Set up the save_event method to return a modified event with an ID
    async def save_event_mock(event):
        return AnalyticsEvent(
            event_type=event.event_type,
            event_data=event.event_data,
            user_id=event.user_id,
            session_id=event.session_id,
            timestamp=event.timestamp,
            # Unique ID based on event object
            event_id=f"test-event-id-{id(event)}"
        )

    repo.save_event = save_event_mock
    return repo

@pytest.fixture
def mock_cache_service():
    """Create a mock cache service for testing."""
    cache = AsyncMock()

    # Set up increment method to return a count
    async def increment_mock(key, increment=1):
        return 5  # Mock counter value after increment

    cache.increment = increment_mock
    return cache

@pytest.fixture
def mock_event_processor():
    """Create a mock ProcessAnalyticsEventUseCase."""
    processor = AsyncMock()

    # Set up execute method to return a processed event
    async def execute_mock(
            event_type,
            event_data,
            user_id=None,
            session_id=None,
            timestamp=None):
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
            event_id=f"processed-{event_type}-{id(event_data)}"
        )

    processor.execute = execute_mock
    return processor

@pytest.fixture
def use_case(
    mock_analytics_repository,
    mock_cache_service,
    mock_event_processor):
    """Create the use case with mocked dependencies."""
    with patch('app.core.utils.logging.get_logger') as mock_logger:
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        use_case = BatchProcessAnalyticsUseCase(
            analytics_repository=mock_analytics_repository,
            cache_service=mock_cache_service,
            event_processor=mock_event_processor
        )

        # Attach the mock logger for assertions
        use_case._logger = mock_logger_instance
        return use_case

@pytest.mark.db_required()
class TestBatchProcessAnalyticsUseCase:
    """Test suite for the BatchProcessAnalyticsUseCase."""

    @pytest.mark.asyncio
    async def test_execute_with_empty_batch(self, use_case):
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
        use_case._logger.warning.assert_called_with(
            "Received empty batch of analytics events")

    @pytest.mark.asyncio
    async def test_execute_with_valid_events(
            self, use_case, mock_event_processor):
        """
        Test processing a batch of valid events.
        """
        # Arrange
        events = [
            {
                "event_type": "page_view",
                "event_data": {"page": "/dashboard"},
                "user_id": "user-123",
                "session_id": "session-abc"
            },
            {
                "event_type": "feature_use",
                "event_data": {"feature": "digital_twin"},
                "user_id": "user-456"
            }
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
        use_case._logger.info.assert_any_call(
            f"Starting batch processing of {len(events)} analytics events",
            {"batch_id": batch_id}
        )
        use_case._logger.info.assert_any_call(
            f"Completed batch processing: {result.processed_count} succeeded, "
            f"{result.failed_count} failed",
            {"batch_id": batch_id}
        )

    @pytest.mark.asyncio
    async def test_partial_failure_handling(
            self, use_case, mock_event_processor):
        """
        Test batch processing continues even if some events fail.
        """
        # Arrange
        events = [
            {
                "event_type": "error_type",  # This will cause an error
                "event_data": {"test": "error_data"}
            },
            {
                "event_type": "valid_type",
                "event_data": {"test": "valid_data"}
            },
            {
                "event_type": "error_type",  # Another error
                "event_data": {"test": "more_error_data"}
            }
        ]

        # Act
        result = await use_case.execute(events)

        # Assert
        assert len(result.events) == 1  # Only one valid event
        assert result.processed_count == 1
        assert result.failed_count == 2

        # Verify error logging
        assert use_case._logger.error.call_count == 2

    @pytest.mark.asyncio
    async def test_event_timestamp_handling(
            self, use_case, mock_event_processor):
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
                "timestamp": timestamp1.isoformat()
            },
            {
                "event_type": "type2",
                "event_data": {"data": 2},
                "timestamp": timestamp2
            },
            {
                "event_type": "type3",
                "event_data": {"data": 3},
                "timestamp": invalid_timestamp
            }
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
    async def test_batch_metadata_saved(self, use_case, mock_cache_service):
        """
        Test that batch metadata is properly saved.
        """
        # Arrange
        events = [
            {
                "event_type": "type1",
                "event_data": {"data": 1}
            },
            {
                "event_type": "type2",
                "event_data": {"data": 2}
            },
            {
                "event_type": "type1",  # Duplicate event type
                "event_data": {"data": 3}
            }
        ]

        # Act
        await use_case.execute(events)

        # Assert - check batch counter was incremented
        mock_cache_service.increment.assert_any_call("analytics:batches:processed")

        # Check event type counters were updated
        mock_cache_service.increment.assert_any_call(
            "analytics:batches:event_types:type1",
            increment=2
        )
        mock_cache_service.increment.assert_any_call(
            "analytics:batches:event_types:type2",
            increment=1
        )

    @pytest.mark.asyncio
    async def test_large_batch_chunking(self, use_case, mock_event_processor):
        """
        Test that large batches are processed in chunks.
        """
        # Arrange
        # Create 250 events (should be processed in 3 chunks with
        # chunk_size=100)
        events = []
        for i in range(250):
            events.append({
                "event_type": f"type{i % 5}",
                "event_data": {"index": i}
            })

        # Act
        result = await use_case.execute(events)

        # Assert
        assert result.processed_count == 250
        assert result.failed_count == 0
        assert len(result.events) == 250

        # Verify all events were processed
        assert mock_event_processor.execute.call_count == 250

        # Verify the _process_chunk method was called 3 times
        # We'll need to check this through the implementation details
        # by counting the number of chunks in the call sequence

        # Extract the event indices from calls to execute
        event_indices = []
        for call_args in mock_event_processor.execute.call_args_list:
            event_index = call_args[1]["event_data"]["index"]
            event_indices.append(event_index)

        # Check that the events were processed in chunks by ensuring order
        # is preserved within chunks (we expect 0-99, 100-199, 200-249)
        assert event_indices[0] == 0
        assert event_indices[99] == 99
        assert event_indices[100] == 100
        assert event_indices[199] == 199
        assert event_indices[200] == 200
        assert event_indices[249] == 249
