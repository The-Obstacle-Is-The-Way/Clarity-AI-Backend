"""
User repository interface definition.

This module defines the contract for user data access operations following
the repository pattern from Domain-Driven Design. It establishes clear
boundaries between the domain and data layers, ensuring proper separation
of concerns according to SOLID principles.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Union
from uuid import UUID

from app.core.domain.entities.user import User


class IUserRepository(ABC):
    """
    Abstract interface for User entity repositories.
    
    This interface defines the contract for all operations related to
    storing and retrieving User entities, following the Repository Pattern.
    Implementations must provide concrete logic for all these operations.
    """
    
    @abstractmethod
    async def get_by_id(self, user_id: Union[str, UUID]) -> Optional[User]:
        """
        Retrieve a user by their unique ID.
        
        Args:
            user_id: Unique identifier for the user
            
        Returns:
            The User entity if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Retrieve a user by their email address.
        
        Args:
            email: Email address of the user
            
        Returns:
            The User entity if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a user by their username.
        
        Args:
            username: Username of the user
            
        Returns:
            The User entity if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def create(self, user: User) -> User:
        """
        Create a new user in the repository.
        
        Args:
            user: User entity to create
            
        Returns:
            The created User entity with any generated IDs/fields populated
            
        Raises:
            DuplicateEntityError: If a user with the same unique fields already exists
        """
        raise NotImplementedError
    
    @abstractmethod
    async def update(self, user: User) -> User:
        """
        Update an existing user in the repository.
        
        Args:
            user: User entity with updated fields
            
        Returns:
            The updated User entity
            
        Raises:
            EntityNotFoundError: If the user doesn't exist
        """
        raise NotImplementedError
    
    @abstractmethod
    async def delete(self, user_id: Union[str, UUID]) -> bool:
        """
        Delete a user from the repository.
        
        Args:
            user_id: Unique identifier for the user to delete
            
        Returns:
            True if deleted successfully, False if not found
        """
        raise NotImplementedError
    
    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        List all users with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of User entities
        """
        raise NotImplementedError
    
    @abstractmethod
    async def count(self) -> int:
        """
        Count the total number of users.
        
        Returns:
            Total count of users in the repository
        """
        raise NotImplementedError