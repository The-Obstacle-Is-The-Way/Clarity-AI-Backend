"""
User Repository domain interface.

This module defines the repository interface for User entities in the domain layer,
following the Repository pattern from Domain-Driven Design to abstract data access operations.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.user import User


class UserRepository(ABC):
    """
    Repository interface for User entities in the domain layer.
    
    This abstract class defines the contract that any concrete repository
    implementation must follow for User data access operations. It follows
    the Repository pattern from Domain-Driven Design, providing a collection-like
    interface for accessing domain objects while encapsulating the underlying
    persistence mechanisms.
    """

    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> User | None:
        """
        Retrieve a user by their unique ID.
        
        Args:
            user_id: The UUID of the user to retrieve
            
        Returns:
            The User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_by_email(self, email: str) -> User | None:
        """
        Retrieve a user by their email address.
        
        Args:
            email: The email address of the user to retrieve
            
        Returns:
            The User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_by_username(self, username: str) -> User | None:
        """
        Retrieve a user by their username.
        
        Args:
            username: The username of the user to retrieve
            
        Returns:
            The User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def create(self, user: User) -> User:
        """
        Create a new user record.
        
        Args:
            user: The User entity to create
            
        Returns:
            The created User entity with any generated fields populated
            
        Raises:
            DuplicateEntityError: If a user with the same unique identifiers already exists
        """
        pass

    @abstractmethod
    async def update(self, user: User) -> User:
        """
        Update an existing user record.
        
        Args:
            user: The User entity with updated fields
            
        Returns:
            The updated User entity
            
        Raises:
            EntityNotFoundError: If the user does not exist
        """
        pass

    @abstractmethod
    async def delete(self, user_id: UUID) -> bool:
        """
        Delete a user record by their ID.
        
        Args:
            user_id: The UUID of the user to delete
            
        Returns:
            True if deletion was successful, False otherwise
            
        Raises:
            EntityNotFoundError: If the user does not exist
        """
        pass

    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[User]:
        """
        List all users with pagination.
        
        Args:
            skip: Number of records to skip for pagination
            limit: Maximum number of records to return
            
        Returns:
            A list of User entities
        """
        pass
    
    @abstractmethod
    async def get_by_role(self, role: str, skip: int = 0, limit: int = 100) -> list[User]:
        """
        Retrieve users by their role.
        
        Args:
            role: The role to filter users by
            skip: Number of records to skip for pagination
            limit: Maximum number of records to return
            
        Returns:
            A list of User entities with the specified role
        """
        pass
    
    @abstractmethod
    async def count(self) -> int:
        """
        Count the total number of users.
        
        Returns:
            The total number of users in the repository
        """
        pass
    
    @abstractmethod
    async def exists(self, user_id: UUID) -> bool:
        """
        Check if a user exists by their ID.
        
        Args:
            user_id: The UUID of the user to check
            
        Returns:
            True if the user exists, False otherwise
        """
        pass
    
    @abstractmethod
    async def exists_by_email(self, email: str) -> bool:
        """
        Check if a user exists by their email.
        
        Args:
            email: The email address to check
            
        Returns:
            True if a user with the given email exists, False otherwise
        """
        pass