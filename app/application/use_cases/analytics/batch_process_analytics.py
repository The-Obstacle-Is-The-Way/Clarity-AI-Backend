"""
Batch Process Analytics Use Case.

This module contains the use case for processing batches of analytics events
asynchronously, providing efficient processing of large volumes of events.
"""

import asyncio
from datetime import datetime
from typing import Any

from app.application.interfaces.repositories.analytics_repository import (
    AnalyticsRepository,
)
from app.application.interfaces.services.cache_service import CacheService
from app.application.use_cases.analytics.process_analytics_event import (
    ProcessAnalyticsEventUseCase,
)
from app.core.utils.logging import get_logger
from app.domain.entities.analytics import AnalyticsBatch, AnalyticsEvent
from app.domain.utils.datetime_utils import UTC


class BatchProcessAnalyticsUseCase:
    """
    Process batches of analytics events asynchronously.

    This use case efficiently handles batches of events, typically used
    for background processing of accumulated events or handling bulk imports.
    """

    def __init__(
        self,
        analytics_repository: AnalyticsRepository,
        cache_service: CacheService,
        event_processor: ProcessAnalyticsEventUseCase | None = None,
    ) -> None:
        """
        Initialize the use case with required dependencies.

        Args:
            analytics_repository: Repository for storing analytics events
            cache_service: Service for caching frequently accessed analytics data
            event_processor: Optional processor for individual events
        """
        self.analytics_repository = analytics_repository
        self.cache_service = cache_service

        # Create event processor if not provided
        if event_processor is None:
            self.event_processor = ProcessAnalyticsEventUseCase(
                analytics_repository=analytics_repository, cache_service=cache_service
            )
        else:
            self.event_processor = event_processor

        self.logger = get_logger(__name__)

    async def execute(
        self, events: list[dict[str, Any]], batch_id: str | None = None
    ) -> AnalyticsBatch:
        """
        Process a batch of analytics events asynchronously.

        Args:
            events: List of event dictionaries to process
            batch_id: Optional identifier for this batch of events

        Returns:
            AnalyticsBatch object with processing results
        """
        if not events:
            self.logger.warning("Received empty batch of analytics events")
            return AnalyticsBatch(
                events=[],
                batch_id=batch_id,
                processed_count=0,
                failed_count=0,
                timestamp=datetime.now(UTC),
            )

        # Log batch processing start (no PHI)
        self.logger.info(
            f"Starting batch processing of {len(events)} analytics events",
            {"batch_id": batch_id},
        )

        # Process events concurrently
        processed_events = []
        failed_count = 0

        # Process in chunks to avoid overwhelming the system
        chunk_size = 100
        for i in range(0, len(events), chunk_size):
            chunk = events[i : i + chunk_size]
            chunk_results = await self._process_chunk(chunk)

            # Track results
            processed_events.extend([e for e in chunk_results if e is not None])
            failed_count += sum(1 for e in chunk_results if e is None)

        # Create batch result
        batch = AnalyticsBatch(
            events=processed_events,
            batch_id=batch_id,
            processed_count=len(processed_events),
            failed_count=failed_count,
            timestamp=datetime.now(UTC),
        )

        # Log completion (no PHI)
        self.logger.info(
            f"Completed batch processing: {batch.processed_count} succeeded, "
            f"{batch.failed_count} failed",
            {"batch_id": batch_id},
        )

        # Save batch metadata if needed
        await self._save_batch_metadata(batch)

        return batch

    async def _process_chunk(
        self, events: list[dict[str, Any]]
    ) -> list[AnalyticsEvent | None]:
        """
        Process a chunk of events concurrently.

        Args:
            events: A chunk of events to process

        Returns:
            List of processed events (None for failed events)
        """
        tasks = []
        for event_data in events:
            # Extract required fields
            event_type = event_data.pop("event_type", None)
            user_id = event_data.pop("user_id", None)
            session_id = event_data.pop("session_id", None)
            timestamp_str = event_data.pop("timestamp", None)

            # Convert timestamp if provided
            timestamp = None
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str)
                except (ValueError, TypeError):
                    timestamp = datetime.now(UTC)

            # Skip invalid events
            if not event_type:
                self.logger.warning("Skipping event with missing event_type")
                tasks.append(None)
                continue

            # Create task for processing this event
            task = asyncio.create_task(
                self._safe_process_event(
                    event_type=event_type,
                    event_data=event_data,
                    user_id=user_id,
                    session_id=session_id,
                    timestamp=timestamp,
                )
            )
            tasks.append(task)

        # Wait for all tasks to complete
        results = []
        for task in tasks:
            if task is None:
                results.append(None)
            else:
                try:
                    result = await task
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Failed to process event: {e!s}")
                    results.append(None)

        return results

    async def _safe_process_event(
        self,
        event_type: str,
        event_data: dict[str, Any],
        user_id: str | None = None,
        session_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> AnalyticsEvent | None:
        """
        Safely process a single event, catching and logging any exceptions.

        Args:
            event_type: Type of the event
            event_data: Event data payload
            user_id: Optional user identifier
            session_id: Optional session identifier
            timestamp: Optional event timestamp

        Returns:
            Processed event or None if processing failed
        """
        try:
            return await self.event_processor.execute(
                event_type=event_type,
                event_data=event_data,
                user_id=user_id,
                session_id=session_id,
                timestamp=timestamp,
            )
        except Exception as e:
            # Log error but continue processing other events
            self.logger.error(
                f"Error processing analytics event: {e!s}",
                {"event_type": event_type, "session_id": session_id},
            )
            return None

    async def _save_batch_metadata(self, batch: AnalyticsBatch) -> None:
        """
        Save metadata about the processed batch for tracking.

        Args:
            batch: The batch that was processed
        """
        # Simply update a counter in cache for now
        # This could be expanded to store more detailed batch metadata
        await self.cache_service.increment("analytics:batches:processed")

        # Update event type counters
        event_type_counts = {}
        for event in batch.events:
            event_type = event.event_type
            if event_type not in event_type_counts:
                event_type_counts[event_type] = 0
            event_type_counts[event_type] += 1

        # Update cache counters for each event type
        for event_type, count in event_type_counts.items():
            await self.cache_service.increment(
                f"analytics:batches:event_types:{event_type}", increment=count
            )
