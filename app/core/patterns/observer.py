# -*- coding: utf-8 -*-
"""
Observer Pattern Implementation.

This module provides a standard implementation of the Observer design pattern.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Callable

from app.core.utils.logging import get_logger

logger = get_logger(__name__)


class Observer(ABC):
    """
    Abstract base class for observers.
    """
    @abstractmethod
    def update(self, event_type: str, data: Any) -> None:
        """
        Receive update from subject.

        Args:
            event_type: The type of event that occurred.
            data: The data associated with the event.
        """
        pass


class Subject:
    """
    The Subject class manages observers and notifies them of events.
    """
    def __init__(self) -> None:
        """Initialize the Subject with an empty list of observers."""
        self._observers: Dict[str, List[Callable[[Any], None]]] = {}

    def attach(self, event_type: str, observer_callback: Callable[[Any], None]) -> None:
        """
        Attach an observer callback for a specific event type.

        Args:
            event_type: The event type to subscribe to.
            observer_callback: The function to call when the event occurs.
        """
        if event_type not in self._observers:
            self._observers[event_type] = []
        if observer_callback not in self._observers[event_type]:
            self._observers[event_type].append(observer_callback)
            logger.debug(f"Attached observer for event: {event_type}")

    def detach(self, event_type: str, observer_callback: Callable[[Any], None]) -> None:
        """
        Detach an observer callback for a specific event type.

        Args:
            event_type: The event type to unsubscribe from.
            observer_callback: The function to remove.
        """
        if event_type in self._observers:
            try:
                self._observers[event_type].remove(observer_callback)
                logger.debug(f"Detached observer for event: {event_type}")
                if not self._observers[event_type]:
                    del self._observers[event_type] # Clean up empty event types
            except ValueError:
                logger.warning(f"Observer callback not found for event: {event_type}")
        else:
             logger.warning(f"No observers found for event type: {event_type}")


    def notify(self, event_type: str, data: Any = None) -> None:
        """
        Notify all observers subscribed to a specific event type.

        Args:
            event_type: The type of event that occurred.
            data: The data associated with the event.
        """
        if event_type in self._observers:
            logger.info(f"Notifying observers for event: {event_type}")
            # Iterate over a copy in case observers detach themselves during notification
            for observer_callback in self._observers[event_type][:]:
                try:
                    observer_callback(data)
                except Exception as e:
                    logger.error(
                        f"Error notifying observer for event {event_type}: {e}",
                        exc_info=True
                    )
        else:
            logger.debug(f"No observers to notify for event: {event_type}")