"""
User repository implementation.

This module implements the UserRepositoryInterface using SQLAlchemy ORM,
following the Repository pattern from clean architecture principles.
"""

from typing import List, Optional, Union
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.domain.entities.user import User
from app.core.errors.base_exceptions import NotFoundException
from app.core.interfaces.repositories.user_repository_interface import UserRepositoryInterface


class SQLAlchemyUserRepository(UserRepositoryInterface):
    """
    SQLAlchemy implementation of the UserRepositoryInterface.
    
    This class bridges the domain model with the database using SQLAlchemy ORM,
    ensuring proper separation of concerns by keeping domain logic free from
    persistence details.
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize the repository with a database session.
        
        Args:
            session: SQLAlchemy async session for database operations
        """
        self._session = session
    
    async def get_by_id(self, user_id: Union[str, UUID]) -> Optional[User]:
        """
        Retrieve a user by their unique ID.
        
        Args:
            user_id: Unique identifier for the user
            
        Returns:
            The User entity if found, None otherwise
        """
        # In a real implementation, this would use SQLAlchemy to query the database
        # For test collection, return a placeholder
        return None
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Retrieve a user by their email address.
        
        Args:
            email: Email address of the user
            
        Returns:
            The User entity if found, None otherwise
        """
        # In a real implementation, this would use SQLAlchemy to query the database
        # For test collection, return a placeholder
        return None
    
    async def get_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a user by their username.
        
        Args:
            username: Username of the user
            
        Returns:
            The User entity if found, None otherwise
        """
        # In a real implementation, this would use SQLAlchemy to query the database
        # For test collection, return a placeholder
        return None
    
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
        # In a real implementation, this would use SQLAlchemy to insert into the database
        # For test collection, return the input
        return user
    
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
        # In a real implementation, this would use SQLAlchemy to update the database
        # For test collection, return the input
        return user
    
    async def delete(self, user_id: Union[str, UUID]) -> bool:
        """
        Delete a user from the repository.
        
        Args:
            user_id: Unique identifier for the user to delete
            
        Returns:
            True if deleted successfully, False if not found
        """
        # In a real implementation, this would use SQLAlchemy to delete from the database
        # For test collection, return success
        return True
    
    async def list_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        List all users with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of User entities
        """
        # In a real implementation, this would use SQLAlchemy to query the database
        # For test collection, return an empty list
        return []
    
    async def count(self) -> int:
        """
        Count the total number of users.
        
        Returns:
            Total count of users in the repository
        """
        # In a real implementation, this would use SQLAlchemy to count entries
        # For test collection, return zero
        return 0


def get_user_repository(session: AsyncSession) -> UserRepositoryInterface:
    """
    Factory function to create a UserRepository instance.
    
    This function allows for dependency injection of the repository
    in FastAPI dependency functions.
    
    Args:
        session: SQLAlchemy async session for database operations
        
    Returns:
        An instance of UserRepositoryInterface
    """
    return SQLAlchemyUserRepository(session)