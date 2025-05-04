"""
Dependencies related to event processing for v1 API.
"""

# from fastapi import Depends # Removed unused import

from app.core.interfaces.services.biometric_event_processor_interface import (
    IBiometricEventProcessor,
)
from app.infrastructure.di.container import get_container


def get_event_processor() -> IBiometricEventProcessor:
    """Provides an instance of the Biometric Event Processor service."""
    container = get_container()
    # Assuming the container is configured to resolve IBiometricEventProcessor
    event_processor_service = container.resolve(IBiometricEventProcessor)
    return event_processor_service
