"""
Interface for the Digital Twin Repository.
"""
from abc import ABC, abstractmethod
from uuid import UUID

# Import directly from the module, not the package
from app.domain.entities.digital_twin import DigitalTwin


# Rename class to match import in DI container -> Renaming back to DigitalTwinRepository
class DigitalTwinRepository(ABC):  # Renamed from DigitalTwinRepositoryInterface
    """Abstract base class defining the digital twin repository interface."""

    @abstractmethod
    async def get_by_id(self, twin_id: UUID) -> DigitalTwin | None:
        """Retrieve a digital twin by its ID."""
        pass

    @abstractmethod
    async def get_by_patient_id(self, patient_id: UUID) -> DigitalTwin | None:
        """Retrieve a digital twin by its associated patient ID."""
        pass

    @abstractmethod
    async def create(self, twin: DigitalTwin) -> DigitalTwin:
        """Create a new digital twin."""
        pass

    @abstractmethod
    async def update(self, twin: DigitalTwin) -> DigitalTwin | None:
        """Update an existing digital twin."""
        pass

    @abstractmethod
    async def delete(self, twin_id: UUID) -> bool:
        """Delete a digital twin by its ID."""
        pass

    # Add other specific query methods if needed, e.g.:
    # @abstractmethod
    # async def list_twins_with_high_risk(self) -> List[DigitalTwin]:
    #     """List twins currently assessed as high risk."""
    #     pass
