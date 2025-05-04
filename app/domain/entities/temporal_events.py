"""
Temporal event entities for digital twin neural network modeling.

This module defines the core entities used to represent temporal events and their 
correlations in the digital twin system, providing the foundation for neural network 
modeling and temporal analysis.
"""

import uuid
from datetime import datetime
from enum import Enum, auto
from typing import Any, Generic, TypeVar
from uuid import UUID

from app.domain.utils.datetime_utils import UTC

T = TypeVar('T')  # Type variable for event values


class CorrelationType(Enum):
    """Types of correlations between events."""
    CAUSAL = auto()           # Direct cause and effect
    SEQUENTIAL = auto()       # Temporal sequence relationship
    ASSOCIATIVE = auto()      # Statistical association
    HIERARCHICAL = auto()     # Parent-child relationship
    PARALLEL = auto()         # Concurrent events
    COMPOUND = auto()         # Multiple correlation types


class TemporalEvent(Generic[T]):
    """
    Base class for all temporal events in the digital twin system.
    
    A temporal event represents a state change, observation, or measurement
    occurring at a specific point in time. It provides the foundation for
    correlation analysis, pattern detection, and event stream processing.
    """
    
    def __init__(
        self,
        timestamp: datetime = None,
        value: T = None,
        event_id: UUID | None = None,
        patient_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        event_type: str = None
    ):
        """
        Initialize a new temporal event.
        
        Args:
            timestamp: When the event occurred
            value: The event's value/payload
            event_id: Unique identifier for the event
            patient_id: Associated patient identifier
            metadata: Additional contextual information
            event_type: Classification of the event
        """
        self.timestamp = timestamp or datetime.now(UTC)
        self.value = value
        self.event_id = event_id or uuid.uuid4()
        self.patient_id = patient_id
        self.metadata = metadata or {}
        self.event_type = event_type or self.__class__.__name__
        
    def to_dict(self) -> dict[str, Any]:
        """
        Convert event to dictionary for serialization.
        
        Returns:
            Dictionary representation of the event
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "value": self.value,
            "event_id": str(self.event_id),
            "patient_id": str(self.patient_id) if self.patient_id else None,
            "metadata": self.metadata,
            "event_type": self.event_type
        }
    
    def __eq__(self, other) -> bool:
        """
        Check if two events are equal.
        
        Args:
            other: Other event to compare with
            
        Returns:
            True if events are equal, False otherwise
        """
        if not isinstance(other, TemporalEvent):
            return False
        
        return (
            self.timestamp == other.timestamp and
            self.value == other.value and
            self.event_id == other.event_id
        )
        
    def __hash__(self) -> int:
        """
        Get hash of the event for use in sets and dictionaries.
        
        Returns:
            Hash value based on event_id
        """
        return hash(self.event_id)


class CorrelatedEvent(TemporalEvent[T]):
    """
    An event that can be correlated with other events.
    
    Extends the base temporal event with correlation capabilities,
    allowing it to participate in complex causal or associative
    relationships with other events.
    """
    
    def __init__(
        self,
        timestamp: datetime = None,
        value: T = None,
        event_id: UUID | None = None,
        patient_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        event_metadata: dict[str, Any] | None = None,
        correlation_type: CorrelationType | None = None,
        correlation_strength: float = 0.0,
        correlated_events: set[UUID] | None = None,
        event_type: str = None,
        correlation_id: UUID | None = None,
        parent_event_id: UUID | None = None
    ):
        """
        Initialize a new correlated event.
        
        Args:
            timestamp: When the event occurred
            value: The event's value/payload
            event_id: Unique identifier for the event
            patient_id: Associated patient identifier
            metadata: Additional contextual information
            correlation_type: Type of correlation
            correlation_strength: Strength of correlation (0.0 to 1.0)
            correlated_events: Set of correlated event IDs
            event_type: Classification of the event
            correlation_id: ID for grouping related events
            parent_event_id: Optional ID of parent event
        """
        # Determine metadata: prefer event_metadata alias if provided
        meta = event_metadata if event_metadata is not None else metadata
        # Initialize base temporal event with metadata
        super().__init__(
            timestamp=timestamp,
            value=value,
            event_id=event_id,
            patient_id=patient_id,
            metadata=meta,
            event_type=event_type
        )
        # Expose event_metadata attribute for repositories and tests
        self.event_metadata = meta or {}
        
        self.correlation_type = correlation_type
        self.correlation_strength = max(0.0, min(1.0, correlation_strength))
        self.correlated_events = correlated_events or set()
        self.correlation_id = correlation_id or self.event_id  # Use provided correlation_id or default to event_id
        self.parent_event_id = parent_event_id  # Use the provided parent_event_id
        # Add id property to match event_id for test compatibility
        self.id = self.event_id
    
    def add_correlated_event(
        self, 
        event_id: UUID,
        correlation_type: CorrelationType = None,
        correlation_strength: float = 0.5
    ) -> None:
        """
        Add a correlation to another event.
        
        Args:
            event_id: ID of the event to correlate with
            correlation_type: Type of correlation
            correlation_strength: Strength of correlation (0.0 to 1.0)
        """
        if event_id == self.event_id:
            return  # Don't correlate with self
            
        self.correlated_events.add(event_id)
        
        # Update correlation type if provided
        if correlation_type is not None:
            self.correlation_type = correlation_type
            
        # Update strength if higher than current
        if correlation_strength > self.correlation_strength:
            self.correlation_strength = min(1.0, correlation_strength)
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert correlated event to dictionary for serialization.
        
        Returns:
            Dictionary representation of the correlated event
        """
        base_dict = super().to_dict()
        base_dict.update({
            "correlation_type": self.correlation_type.name if self.correlation_type else None,
            "correlation_strength": self.correlation_strength,
            "correlated_events": [str(e) for e in self.correlated_events],
            "correlation_id": str(self.correlation_id),
            "parent_event_id": str(self.parent_event_id) if self.parent_event_id else None
        })
        return base_dict
    
    @classmethod
    def create_child_event(
        cls,
        parent_event: 'CorrelatedEvent',
        event_type: str,
        **kwargs
    ) -> 'CorrelatedEvent':
        """
        Create a child event from a parent event.
        
        Args:
            parent_event: The parent event
            event_type: Type of the child event
            **kwargs: Additional attributes for the child event
            
        Returns:
            A new child event with correlation to the parent
        """
        # Extract metadata for child event
        metadata = kwargs.pop('metadata', {}) or {}
        
        # Create the child event
        child_event = cls(
            event_type=event_type,
            metadata=metadata,
            timestamp=datetime.now(UTC)
        )
        
        # Set correlation ID to match parent
        child_event.correlation_id = parent_event.correlation_id
        
        # Set parent event ID
        child_event.parent_event_id = parent_event.event_id
        
        return child_event


class EventChain:
    """
    A chain of causally connected temporal events.
    
    This class represents a sequence of events that form a causal chain,
    useful for analyzing event propagation and effects over time.
    """
    
    def __init__(
        self,
        correlation_id: UUID | None = None,
        name: str | None = None,
        description: str | None = None,
        chain_id: UUID | None = None,
        patient_id: UUID | None = None,
        events: list[CorrelatedEvent] | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: datetime | None = None
    ):
        """
        Initialize a new event chain.
        
        Args:
            correlation_id: ID used to correlate events in this chain
            name: Name of the chain
            chain_id: Unique identifier for the chain
            patient_id: Identifier of the associated patient
            events: Ordered list of events in this chain
            metadata: Additional metadata for the chain
            created_at: Creation timestamp
        """
        # Assign or generate correlation ID
        if correlation_id is None:
            correlation_id = uuid.uuid4()
        self.correlation_id = correlation_id
        # Optional description for the chain
        self.description = description
        self.name = name or f"Chain-{str(correlation_id)[:8]}"
        self.chain_id = chain_id or uuid.uuid4()
        self.patient_id = patient_id
        self.events = events or []
        self.metadata = metadata or {}
        self.created_at = created_at or datetime.now(UTC)
    
    def add_event(self, event: CorrelatedEvent) -> None:
        """
        Add an event to the chain.
        
        Args:
            event: The event to add
            
        Raises:
            ValueError: If the event doesn't match the chain's correlation ID
        """
        # For the first event, adopt its correlation ID
        if not self.events:
            self.correlation_id = event.correlation_id
        # For subsequent events, ensure matching correlation
        elif event.correlation_id != self.correlation_id:
            raise ValueError(
                f"Event correlation ID {event.correlation_id} does not match "
                f"chain correlation ID {self.correlation_id}"
            )
        self.events.append(event)
    
    @property
    def root_event_id(self) -> UUID | None:
        """Return the ID of the root (first) event in the chain."""
        if self.events:
            return self.events[0].event_id
        return None

    @property
    def last_event_id(self) -> UUID | None:
        """Return the ID of the last event in the chain."""
        if self.events:
            return self.events[-1].event_id
        return None
    
    def get_root_event(self) -> CorrelatedEvent | None:
        """
        Get the root event (event with no parent) in the chain.
        
        Returns:
            The root event, or None if no events in chain
        """
        if not self.events:
            return None
            
        for event in self.events:
            if event.parent_event_id is None:
                return event
                
        # If no root event found, return the first event
        return self.events[0]
        
    def get_child_events(self, parent_id: UUID) -> list[CorrelatedEvent]:
        """
        Get all events that have the specified event as their parent.
        
        Args:
            parent_id: ID of the parent event
            
        Returns:
            List of child events
        """
        return [event for event in self.events if event.parent_event_id == parent_id]
    
    def get_event_by_id(self, event_id: UUID) -> CorrelatedEvent | None:
        """
        Get an event by its ID.
        
        Args:
            event_id: ID of the event to retrieve
            
        Returns:
            The event with the specified ID, or None if not found
        """
        for event in self.events:
            if event.event_id == event_id:
                return event
        
        return None
        
    def get_events_by_type(self, event_type: str) -> list[CorrelatedEvent]:
        """
        Get all events of a specific type in the chain.
        
        Args:
            event_type: The type of events to retrieve
            
        Returns:
            List of events matching the specified type
        """
        return [event for event in self.events if event.event_type == event_type]
    
    def find_event_by_type(self, event_type: str) -> CorrelatedEvent | None:
        """Find the first event of the given type in the chain."""
        events = self.get_events_by_type(event_type)
        return events[0] if events else None
    
    def get_event_path(self, event_id: UUID) -> list[CorrelatedEvent]:
        """
        Get the path of events from the root to the specified event.
        Returns a list of CorrelatedEvent instances in order.
        """
        path: list[CorrelatedEvent] = []
        # Find the target event
        event = self.get_event_by_id(event_id)
        # Traverse up via parent_event_id
        while event is not None:
            path.append(event)
            if not hasattr(event, 'parent_event_id') or event.parent_event_id is None:
                break
            event = self.get_event_by_id(event.parent_event_id)
        # Return from root to target
        return list(reversed(path))
        
    def build_event_tree(self) -> dict[UUID, list[UUID]]:
        """
        Build a mapping of event IDs to their child event IDs.
        
        Returns:
            A dictionary where keys are event IDs and values are lists of child event IDs
        """
        # Initialize the tree
        tree = {}
        
        # Process each event
        for event in self.events:
            # Find all children of this event
            children = self.get_child_events(event.event_id)
            
            # If there are children, add to the tree
            if children:
                tree[event.event_id] = [child.event_id for child in children]
                
        return tree
        
    def rebuild_hierarchy(self) -> None:
        """
        Rebuild the internal hierarchy of events in the chain.
        This is a no-op placeholder; actual hierarchy logic may be implemented as needed.
        """
        return None

    def to_dict(self) -> dict[str, Any]:
        """
        Convert chain to dictionary for serialization.
        
        Returns:
            Dictionary representation of the chain
        """
        result = {
            "name": self.name,
            "correlation_id": str(self.correlation_id),
            "chain_id": str(self.chain_id),
            "created_at": self.created_at.isoformat(),
            "event_count": len(self.events),
            "metadata": self.metadata,
            "patient_id": str(self.patient_id) if self.patient_id else None,
            "events": [event.to_dict() for event in self.events[:100]]  # Limit to first 100 for performance
        }
        # Include root and last event identifiers
        result["root_event_id"] = self.root_event_id
        result["last_event_id"] = self.last_event_id
        return result


class EventGroup:
    """
    A collection of related but not necessarily causally connected events.
    
    This class provides a means to group related events for analysis without
    requiring a strict causal relationship between them.
    """
    
    def __init__(
        self,
        name: str,
        description: str | None = None,
        group_id: UUID | None = None,
        patient_id: UUID | None = None,
        events: list[TemporalEvent] | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: datetime | None = None
    ):
        """
        Initialize a new event group.
        
        Args:
            name: Name of the group
            description: Description of the group
            group_id: Unique identifier for the group
            patient_id: Identifier of the associated patient
            events: List of events in this group
            metadata: Additional metadata for the group
            created_at: Creation timestamp
        """
        self.name = name
        self.description = description or ""
        self.group_id = group_id or uuid.uuid4()
        self.patient_id = patient_id
        self.events = events or []
        self.metadata = metadata or {}
        self.created_at = created_at or datetime.now(UTC)
    
    def add_event(self, event: TemporalEvent) -> None:
        """
        Add an event to the group.
        
        Args:
            event: The temporal event to add
        """
        self.events.append(event)
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert group to dictionary for serialization.
        
        Returns:
            Dictionary representation of the group
        """
        return {
            "name": self.name,
            "description": self.description,
            "group_id": str(self.group_id),
            "created_at": self.created_at.isoformat(),
            "event_count": len(self.events),
            "metadata": self.metadata,
            "patient_id": str(self.patient_id) if self.patient_id else None,
            "events": [event.to_dict() for event in self.events[:100]]  # Limit to first 100 for performance
        }