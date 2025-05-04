import logging
from typing import Any

from app.core.interfaces.services.biometric_event_processor_interface import (
    IBiometricEventProcessor,
)

logger = logging.getLogger(__name__)


class BiometricEventProcessor(IBiometricEventProcessor):
    """Placeholder implementation for processing biometric events."""

    async def process_event(self, event_data: Any) -> None:
        """Process a single biometric event (placeholder)."""
        logger.info(f"Processing biometric event (placeholder): {event_data}")
        # Actual processing logic will be implemented here later.
        pass


def get_biometric_event_processor() -> BiometricEventProcessor:
    """Factory function for BiometricEventProcessor."""
    # Add any necessary dependencies here if needed in the future
    return BiometricEventProcessor()
