from abc import ABC, abstractmethod
from typing import Any


class IBiometricEventProcessor(ABC):
    """Interface for processing biometric events."""

    @abstractmethod
    async def process_event(self, event_data: Any) -> None:
        """Process a single biometric event."""
        raise NotImplementedError
