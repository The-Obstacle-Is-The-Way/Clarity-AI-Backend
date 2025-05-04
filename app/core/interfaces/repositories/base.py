"""
Base Repository Interface.

Defines the contract for the base repository pattern implementation
following clean architecture principles.
"""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

# Entity type variable
T = TypeVar('T')

class IRepository(Generic[T], ABC):
    """
    Abstract base class for repository pattern implementation.
    
    This interface defines the standard operations to be implemented
    by all concrete repositories, providing a uniform access pattern
    across the application for data persistence operations.
    """
    
    @abstractmethod
    async def get_by_id(self, id: Any) -> T | None:
        """Retrieve an entity by its unique identifier."""
        pass
    
    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[T]:
        """Retrieve a collection of entities with pagination support."""
        pass
    
    @abstractmethod
    async def create(self, entity: T) -> T:
        """Create a new entity record."""
        pass
    
    @abstractmethod
    async def update(self, entity: T) -> T:
        """Update an existing entity record."""
        pass
    
    @abstractmethod
    async def delete(self, id: Any) -> bool:
        """Delete an entity by its ID. Returns True if deletion was successful."""
        pass