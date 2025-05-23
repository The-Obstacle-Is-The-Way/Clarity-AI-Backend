"""Interface definition for Biometric Alert Repository."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from app.domain.entities.biometric_alert import BiometricAlert


class IBiometricAlertRepository(ABC):
    """Repository interface for BiometricAlert entities."""

    @abstractmethod
    async def get_by_id(self, alert_id: UUID) -> BiometricAlert | None:
        """Retrieve a biometric alert by its unique ID."""
        pass

    @abstractmethod
    async def get_by_patient_id(
        self, patient_id: UUID, limit: int = 100, skip: int = 0
    ) -> list[BiometricAlert]:
        """Retrieve biometric alerts for a specific patient."""
        pass

    @abstractmethod
    async def create(self, alert: BiometricAlert) -> BiometricAlert:
        """Create a new biometric alert record."""
        pass

    @abstractmethod
    async def update(self, alert: BiometricAlert) -> BiometricAlert:
        """Update an existing biometric alert record."""
        pass

    @abstractmethod
    async def delete(self, alert_id: UUID) -> bool:
        """Delete a biometric alert record by its ID."""
        pass
