"""
Interface for the Digital Twin Repository.
"""
from abc import abstractmethod
from uuid import UUID

from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
# Import directly from the module, not the package
from app.domain.entities.digital_twin import DigitalTwin


# Rename class to match import in DI container -> Renaming back to DigitalTwinRepository
class DigitalTwinRepository(BaseRepositoryInterface[DigitalTwin]):  # Renamed from DigitalTwinRepositoryInterface
    """Abstract base class defining the digital twin repository interface."""

    @abstractmethod
    async def get_by_id(self, entity_id: str | UUID) -> DigitalTwin | None:
        """Retrieve a digital twin by its ID."""
        pass

    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[DigitalTwin]:
        """List all digital twins with pagination."""
        pass

    @abstractmethod
    async def create(self, entity: DigitalTwin) -> DigitalTwin:
        """Create a new digital twin."""
        pass

    @abstractmethod
    async def update(self, entity: DigitalTwin) -> DigitalTwin:
        """Update an existing digital twin."""
        pass

    @abstractmethod
    async def delete(self, entity_id: str | UUID) -> bool:
        """Delete a digital twin by its ID."""
        pass

    @abstractmethod
    async def count(self, **filters) -> int:
        """Count digital twins matching optional filters."""
        pass

    @abstractmethod
    async def get_by_patient_id(self, patient_id: UUID) -> DigitalTwin | None:
        """Retrieve a digital twin by its associated patient ID."""
        pass

    # Add other specific query methods if needed, e.g.:
    # @abstractmethod
    # async def list_twins_with_high_risk(self) -> List[DigitalTwin]:
    #     """List twins currently assessed as high risk."""
    #     pass
