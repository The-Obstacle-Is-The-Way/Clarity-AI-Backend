"""Interface definition for Biometric Rule Repository.

Defines the contract for data access operations related to Biometric Rule entities.
"""

from abc import ABC, abstractmethod
from uuid import UUID

# Import BiometricRule entity - use Any as fallback if import fails
try:
    from app.domain.entities.biometric_rule import BiometricRule
except ImportError:
    from typing import Any

    BiometricRule = Any


class IBiometricRuleRepository(ABC):
    """Abstract base class for biometric rule data persistence operations."""

    @abstractmethod
    async def get_by_id(self, rule_id: UUID) -> BiometricRule | None:
        """Retrieve a biometric rule by its unique ID."""
        pass

    @abstractmethod
    async def get_by_patient_id(
        self, patient_id: UUID, limit: int = 100, skip: int = 0
    ) -> list[BiometricRule]:
        """Retrieve biometric rules for a specific patient."""
        pass

    @abstractmethod
    async def create(self, rule: BiometricRule) -> BiometricRule:
        """Create a new biometric rule record."""
        pass

    @abstractmethod
    async def update(self, rule: BiometricRule) -> BiometricRule:
        """Update an existing biometric rule record."""
        pass

    @abstractmethod
    async def delete(self, rule_id: UUID) -> bool:
        """Delete a biometric rule record by its ID. Returns True if deletion was successful."""
        pass

    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[BiometricRule]:
        """List all biometric rules with pagination."""
        pass

    @abstractmethod
    async def get_active_rules(
        self, patient_id: UUID | None = None
    ) -> list[BiometricRule]:
        """Retrieve active (enabled) rules, optionally filtered by patient."""
        pass
