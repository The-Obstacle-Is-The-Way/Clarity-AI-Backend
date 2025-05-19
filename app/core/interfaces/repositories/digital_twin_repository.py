"""Interface definition for Digital Twin Repository.

Defines the contract for data access operations related to Digital Twin entities.
Following clean architecture principles, this interface is in the core layer
and defines the port for repository implementations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

# Import DigitalTwin entity - use Any as fallback if import fails
try:
    from app.domain.entities.digital_twin import DigitalTwin
except ImportError:
    from typing import Any

    DigitalTwin = Any


class IDigitalTwinRepository(ABC):
    """Abstract base class for digital twin data persistence operations."""

    @abstractmethod
    async def get_by_id(self, twin_id: UUID) -> DigitalTwin | None:
        """Retrieve a digital twin by its unique ID."""
        pass

    @abstractmethod
    async def get_by_patient_id(self, patient_id: UUID) -> DigitalTwin | None:
        """Retrieve the digital twin for a specific patient."""
        pass

    @abstractmethod
    async def create(self, twin: DigitalTwin) -> DigitalTwin:
        """Create a new digital twin record."""
        pass

    @abstractmethod
    async def update(self, twin: DigitalTwin) -> DigitalTwin:
        """Update an existing digital twin record."""
        pass

    @abstractmethod
    async def delete(self, twin_id: UUID) -> bool:
        """Delete a digital twin record by its ID. Returns True if deletion was successful."""
        pass

    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[DigitalTwin]:
        """List all digital twins with pagination."""
        pass

    @abstractmethod
    async def update_twin_state(
        self, patient_id: UUID, state_updates: dict[str, Any]
    ) -> DigitalTwin:
        """Update specific aspects of a digital twin's state."""
        pass

    @abstractmethod
    async def get_twin_history(
        self,
        patient_id: UUID,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get historical state changes for a digital twin."""
        pass

    @abstractmethod
    async def create_session(
        self,
        patient_id: UUID,
        session_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create a new interaction session with the digital twin. Returns session ID."""
        pass

    @abstractmethod
    async def end_session(self, session_id: str) -> bool:
        """End an active digital twin session. Returns True if successful."""
        pass
