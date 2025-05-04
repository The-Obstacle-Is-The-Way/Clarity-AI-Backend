"""
Base repository interface definition.

This module defines the foundational repository interface
following the Repository Pattern from Domain-Driven Design.
All concrete repository interfaces should extend this base.
"""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar
from uuid import UUID

# Generic type variable for domain entities
T = TypeVar('T')


class BaseRepositoryInterface(Generic[T], ABC):
    """
    Base interface for all repository implementations.
    
    This interface establishes the standard contract for data access operations
    that all repository implementations must follow, ensuring consistent data
    access patterns across the application.
    """
    
    @abstractmethod
    async def get_by_id(self, entity_id: str | UUID) -> T | None:
        """
        Retrieve an entity by its unique ID.
        
        Args:
            entity_id: The unique identifier of the entity
            
        Returns:
            The entity if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[T]:
        """
        Retrieve a paginated list of all entities.
        
        Args:
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return
            
        Returns:
            List of entities
        """
        raise NotImplementedError
    
    @abstractmethod
    async def create(self, entity: T) -> T:
        """
        Create a new entity in the repository.
        
        Args:
            entity: The entity to create
            
        Returns:
            The created entity with any generated fields populated
            
        Raises:
            DuplicateEntityError: If an entity with the same unique fields already exists
        """
        raise NotImplementedError
    
    @abstractmethod
    async def update(self, entity: T) -> T:
        """
        Update an existing entity in the repository.
        
        Args:
            entity: The entity with updated fields
            
        Returns:
            The updated entity
            
        Raises:
            EntityNotFoundError: If the entity doesn't exist
        """
        raise NotImplementedError
    
    @abstractmethod
    async def delete(self, entity_id: str | UUID) -> bool:
        """
        Delete an entity from the repository.
        
        Args:
            entity_id: The unique identifier of the entity to delete
            
        Returns:
            True if deleted successfully, False if not found
        """
        raise NotImplementedError
        
    @abstractmethod
    async def count(self, **filters) -> int:
        """
        Count the number of entities matching the given filters.
        
        Args:
            **filters: Optional filtering criteria
            
        Returns:
            The count of matching entities
        """
        raise NotImplementedError