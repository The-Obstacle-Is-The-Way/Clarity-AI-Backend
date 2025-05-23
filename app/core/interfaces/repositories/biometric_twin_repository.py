"""Interface definition for Biometric Twin Repository.

Defines the contract for data access operations related to Biometric Twin entities.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.domain.entities.biometric_twin import BiometricTwinState


class IBiometricTwinRepository(ABC):
    """Abstract base class for biometric twin data persistence operations."""

    @abstractmethod
    async def get_by_id(self, twin_id: UUID) -> BiometricTwinState | None:
        """Retrieve a biometric twin by its unique ID."""
        pass

    @abstractmethod
    async def get_by_patient_id(self, patient_id: UUID) -> BiometricTwinState | None:
        """Retrieve a biometric twin for a specific patient."""
        pass

    @abstractmethod
    async def create(self, twin: BiometricTwinState) -> BiometricTwinState:
        """Create a new biometric twin record."""
        pass

    @abstractmethod
    async def update(self, twin: BiometricTwinState) -> BiometricTwinState:
        """Update an existing biometric twin record."""
        pass

    @abstractmethod
    async def delete(self, twin_id: UUID) -> bool:
        """Delete a biometric twin record by its ID. Returns True if deletion was successful."""
        pass

    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[BiometricTwinState]:
        """List all biometric twins with pagination."""
        pass

    @abstractmethod
    async def add_data_point(
        self,
        patient_id: UUID,
        data_type: str,
        value: float | int | bool | dict[str, Any],
        timestamp: datetime | None = None,
    ) -> BiometricTwinState:
        """Add a new data point to a patient's biometric twin."""
        pass

    @abstractmethod
    async def get_latest_data(
        self, patient_id: UUID, data_type: str | None = None
    ) -> dict[str, Any]:
        """Get the latest biometric data for a patient, optionally filtered by data type."""
        pass

    @abstractmethod
    async def get_data_history(
        self,
        patient_id: UUID,
        data_type: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get historical biometric data for a patient."""
        pass
