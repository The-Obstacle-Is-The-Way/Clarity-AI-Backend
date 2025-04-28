"""
User repository interface for accessing user data.

This module defines the User repository interface following the
repository pattern, which abstracts data access operations from
business logic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.user import User


class UserRepository(ABC):
    """
    User repository interface.
    
    This abstract class defines the contract for user data access
    operations, following the repository pattern.
    """
    
    @abstractmethod
    async def create(self, user: User) -> User:
        """
        Create a new user.
        
        Args:
            user: User entity to create
            
        Returns:
            Created user with assigned ID
        """
        pass
    
    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> User | None:
        """
        Get a user by ID.
        
        Args:
            user_id: UUID of the user
            
        Returns:
            User if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_by_email(self, email: str) -> User | None:
        """
        Get a user by email.
        
        Args:
            email: Email address of the user
            
        Returns:
            User if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def update(self, user: User) -> User:
        """
        Update a user.
        
        Args:
            user: User entity with updated values
            
        Returns:
            Updated user
        """
        pass
    
    @abstractmethod
    async def delete(self, user_id: UUID) -> bool:
        """
        Delete a user.
        
        Args:
            user_id: UUID of the user to delete
            
        Returns:
            True if deleted, False if not found
        """
        pass
    
    @abstractmethod
    async def list_users(self, skip: int = 0, limit: int = 100) -> list[User]:
        """
        List users with pagination.
        
        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return
            
        Returns:
            List of users
        """
        pass
    
    @abstractmethod
    async def get_by_role(self, role: str, skip: int = 0, limit: int = 100) -> list[User]:
        """
        Get users by role.
        
        Args:
            role: Role to filter by
            skip: Number of users to skip
            limit: Maximum number of users to return
            
        Returns:
            List of users with the specified role
        """
        pass