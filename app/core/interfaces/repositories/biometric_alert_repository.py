"""Interface definition for Biometric Alert Repository.

Defines the contract for data access operations related to Biometric Alert entities.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

# Import BiometricAlert entity - use Any as fallback if import fails
try:
    from app.domain.entities.biometric_alert import BiometricAlert
except ImportError:
    from typing import Any
    BiometricAlert = Any


class IBiometricAlertRepository(ABC):
    """Abstract base class for biometric alert data persistence operations."""

    @abstractmethod
    async def get_by_id(self, alert_id: UUID) -> Optional[BiometricAlert]:
        """Retrieve a biometric alert by its unique ID."""
        pass

    @abstractmethod
    async def get_by_patient_id(self, patient_id: UUID, limit: int = 100, skip: int = 0) -> List[BiometricAlert]:
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
        """Delete a biometric alert record by its ID. Returns True if deletion was successful."""
        pass

    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> List[BiometricAlert]:
        """List all biometric alerts with pagination."""
        pass
    
    @abstractmethod
    async def acknowledge(self, alert_id: UUID) -> BiometricAlert:
        """Mark an alert as acknowledged."""
        pass
    
    @abstractmethod
    async def resolve(self, alert_id: UUID) -> BiometricAlert:
        """Mark an alert as resolved."""
        pass
    
    @abstractmethod
    async def get_active_alerts(self, patient_id: Optional[UUID] = None, limit: int = 100, skip: int = 0) -> List[BiometricAlert]:
        """Retrieve active (unresolved) alerts, optionally filtered by patient."""
        pass