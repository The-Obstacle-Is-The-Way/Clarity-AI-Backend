"""
Repository interfaces for temporal data storage and retrieval.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.temporal_events import CorrelatedEvent, EventChain
from app.domain.entities.temporal_sequence import TemporalSequence


class TemporalSequenceRepository(ABC):
    """
    Repository interface for temporal sequence operations.

    Defines the contract for persistence operations on temporal sequences.
    """

    @abstractmethod
    async def save(self, sequence: TemporalSequence) -> UUID:
        """
        Persist a temporal sequence.

        Args:
            sequence: The domain entity to persist

        Returns:
            UUID of the saved sequence
        """
        pass

    @abstractmethod
    async def get_by_id(self, sequence_id: UUID) -> TemporalSequence | None:
        """
        Retrieve a temporal sequence by ID.

        Args:
            sequence_id: UUID of the sequence to retrieve

        Returns:
            TemporalSequence if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_by_patient_id(self, patient_id: UUID) -> list[TemporalSequence]:
        """
        Get all temporal sequences for a patient.

        Args:
            patient_id: UUID of the patient

        Returns:
            List of temporal sequences
        """
        pass

    @abstractmethod
    async def delete(self, sequence_id: UUID) -> bool:
        """
        Delete a temporal sequence.

        Args:
            sequence_id: UUID of the sequence to delete

        Returns:
            True if deletion was successful
        """
        pass

    @abstractmethod
    async def get_latest_by_feature(
        self, patient_id: UUID, feature_name: str, limit: int = 10
    ) -> TemporalSequence | None:
        """
        Get the most recent temporal sequence containing a specific feature.

        Args:
            patient_id: UUID of the patient
            feature_name: Name of the feature to find
            limit: Maximum number of entries to return

        Returns:
            The most recent temporal sequence containing the feature
        """
        pass


class EventRepository(ABC):
    """
    Repository interface for event persistence operations.

    Defines the contract for storing and retrieving correlated events.
    """

    @abstractmethod
    async def save_event(self, event: CorrelatedEvent) -> UUID:
        """
        Save a single event.

        Args:
            event: The event to save

        Returns:
            UUID of the saved event
        """
        pass

    @abstractmethod
    async def get_event_by_id(self, event_id: UUID) -> CorrelatedEvent | None:
        """
        Get an event by its ID.

        Args:
            event_id: UUID of the event

        Returns:
            CorrelatedEvent if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_events_by_correlation_id(self, correlation_id: UUID) -> list[CorrelatedEvent]:
        """
        Get all events with the specified correlation ID.

        Args:
            correlation_id: The correlation ID to search for

        Returns:
            List of correlated events
        """
        pass

    @abstractmethod
    async def get_event_chain(self, correlation_id: UUID) -> EventChain:
        """
        Get a complete event chain by correlation ID.

        Args:
            correlation_id: The correlation ID of the chain

        Returns:
            EventChain containing all related events
        """
        pass

    @abstractmethod
    async def get_patient_events(
        self, patient_id: UUID, event_type: str | None = None, limit: int = 100
    ) -> list[CorrelatedEvent]:
        """
        Get events associated with a patient.

        Args:
            patient_id: UUID of the patient
            event_type: Optional filter for event type
            limit: Maximum number of events to return

        Returns:
            List of events matching the criteria
        """
        pass
