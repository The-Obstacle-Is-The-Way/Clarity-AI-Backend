"""
Event types and observer patterns for the XGBoost service.

This module defines event types and observer interfaces for implementing
the Observer pattern in the XGBoost service.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any


class EventType(Enum):
    """Enumeration of event types for the XGBoost service."""

    # Configuration events
    CONFIGURATION_VALIDATED = "config_validated"
    CONFIGURATION_ERROR = "config_error"

    # Prediction events
    PREDICTION_START = "prediction_start"
    PREDICTION_SUCCESS = "prediction_success"
    PREDICTION_FAILURE = "prediction_failure"

    # Validation events
    VALIDATION_START = "validation_start"
    VALIDATION_SUCCESS = "validation_success"
    VALIDATION_ERROR = "validation_error"

    # Model events
    MODEL_LOADED = "model_loaded"
    MODEL_ERROR = "model_error"
    MODEL_TIMEOUT = "model_timeout"

    # AWS service events
    SERVICE_UNAVAILABLE = "service_unavailable"
    AWS_ERROR = "aws_error"

    # Feature events
    FEATURE_IMPORTANCE_COMPUTED = "feature_importance_computed"
    FEATURE_VALIDATION_ERROR = "feature_validation_error"

    # Metrics events
    METRICS_FETCHED = "metrics_fetched"
    METRICS_NOT_FOUND = "metrics_not_found"

    # General events
    UNEXPECTED_ERROR = "unexpected_error"


class Observer(ABC):
    """
    Observer interface for the Observer pattern.

    Implementations of this interface can be registered with the XGBoost service
    to receive notifications when specific events occur.
    """

    @abstractmethod
    def update(self, event_type: EventType, data: dict[str, Any]) -> None:
        """
        Update method called when an observed event occurs.

        Args:
            event_type: Type of event that occurred
            data: Event data
        """
        pass


class Observable(ABC):
    """
    Observable interface for the Observer pattern.

    Provides methods for registering and notifying observers.
    """

    @abstractmethod
    def register_observer(self, event_type: EventType, observer: Observer) -> None:
        """
        Register an observer for a specific event type.

        Args:
            event_type: Type of event to observe
            observer: Observer to register
        """
        pass

    @abstractmethod
    def unregister_observer(self, event_type: EventType, observer: Observer) -> None:
        """
        Unregister an observer for a specific event type.

        Args:
            event_type: Type of event to stop observing
            observer: Observer to unregister
        """
        pass
