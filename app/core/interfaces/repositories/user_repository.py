# -*- coding: utf-8 -*-
"""
Interface definition for User Repository.

Defines the contract for data access operations related to User entities.
"""

from abc import ABC, abstractmethod
from typing import Optional, List
from uuid import UUID

# Import User entity - use Any as fallback if import fails
try:
    from app.domain.entities.user import User
except ImportError:
    User = Any

class IUserRepository(ABC):
    """Abstract base class for user data persistence operations."""

    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        """Retrieve a user by their unique ID."""
        pass

    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user by their email address."""
        pass

    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Retrieve a user by their username."""
        pass

    @abstractmethod
    async def create(self, user: User) -> User:
        """Create a new user record."""
        pass

    @abstractmethod
    async def update(self, user: User) -> User:
        """Update an existing user record."""
        pass

    @abstractmethod
    async def delete(self, user_id: UUID) -> bool:
        """Delete a user record by their ID. Returns True if deletion was successful."""
        pass

    @abstractmethod
    async def list_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """List all users with pagination."""
        pass 