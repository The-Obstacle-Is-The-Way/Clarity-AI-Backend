"""
SQL Alchemy implementation of the user repository.

This module provides a concrete implementation of the UserRepository interface
using SQLAlchemy for database operations.
"""
from typing import List, Optional
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

# Corrected import for password hashing function
from app.infrastructure.security.password.hashing import get_password_hash
from app.domain.entities.user import User
from app.domain.repositories.user_repository import UserRepository
from app.infrastructure.models.user_model import UserModel
from app.infrastructure.persistence.sqlalchemy.config.database import DBSessionDep


class SqlAlchemyUserRepository(UserRepository):
    """
    SQL Alchemy implementation of the UserRepository interface.
    
    This class provides methods for accessing and manipulating user data
    using SQLAlchemy ORM for database operations.
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize the repository with a database session.
        
        Args:
            session: SQLAlchemy async session for database operations
        """
        self.session = session
    
    async def create(self, user: User) -> User:
        """
        Create a new user in the database.
        
        Args:
            user: User entity to create
            
        Returns:
            Created user with database ID
        """
        user_model = UserModel(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            hashed_password=user.hashed_password,
            is_active=user.is_active,
            roles=user.roles,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
        
        self.session.add(user_model)
        await self.session.flush()
        
        return self._model_to_entity(user_model)
    
    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        """
        Get a user by ID.
        
        Args:
            user_id: UUID of the user
            
        Returns:
            User if found, None otherwise
        """
        result = await self.session.execute(
            sa.select(UserModel).where(UserModel.id == user_id)
        )
        user_model = result.scalars().first()
        
        if not user_model:
            return None
        
        return self._model_to_entity(user_model)
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get a user by email.
        
        Args:
            email: Email address of the user
            
        Returns:
            User if found, None otherwise
        """
        result = await self.session.execute(
            sa.select(UserModel).where(UserModel.email == email)
        )
        user_model = result.scalars().first()
        
        if not user_model:
            return None
        
        return self._model_to_entity(user_model)
    
    async def get_by_username(self, username: str) -> Optional[User]:
        """
        Get a user by username.
        
        Args:
            username: Username or email of the user
            
        Returns:
            User if found, None otherwise
        """
        # Check if this is an email and use the email lookup
        if '@' in username:
            return await self.get_by_email(username)
        
        # Look up by username
        result = await self.session.execute(
            sa.select(UserModel).where(UserModel.username == username)
        )
        user_model = result.scalars().first()
        
        if not user_model:
            return None
        
        return self._model_to_entity(user_model)
    
    async def update(self, user: User) -> User:
        """
        Update a user.
        
        Args:
            user: User entity with updated values
            
        Returns:
            Updated user
        """
        result = await self.session.execute(
            sa.select(UserModel).where(UserModel.id == user.id)
        )
        user_model = result.scalars().first()
        
        if not user_model:
            raise ValueError(f"User with ID {user.id} not found")
        
        # Update model fields
        user_model.email = user.email
        user_model.first_name = user.first_name
        user_model.last_name = user.last_name
        user_model.hashed_password = user.hashed_password
        user_model.is_active = user.is_active
        user_model.roles = user.roles
        user_model.updated_at = user.updated_at
        
        await self.session.flush()
        
        return self._model_to_entity(user_model)
    
    async def delete(self, user_id: UUID) -> bool:
        """
        Delete a user.
        
        Args:
            user_id: UUID of the user to delete
            
        Returns:
            True if deleted, False if not found
        """
        result = await self.session.execute(
            sa.delete(UserModel).where(UserModel.id == user_id)
        )
        
        await self.session.flush()
        
        return result.rowcount > 0
    
    async def list_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        List users with pagination.
        
        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return
            
        Returns:
            List of users
        """
        result = await self.session.execute(
            sa.select(UserModel)
            .offset(skip)
            .limit(limit)
            .order_by(UserModel.email)
        )
        
        user_models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in user_models]
    
    async def get_by_role(self, role: str, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get users by role.
        
        Args:
            role: Role to filter by
            skip: Number of users to skip
            limit: Maximum number of users to return
            
        Returns:
            List of users with the specified role
        """
        # Using array contains operator for PostgreSQL
        # This assumes roles are stored as an array in PostgreSQL
        # Note: SQLite doesn't support this directly, so may need a different approach there
        result = await self.session.execute(
            sa.select(UserModel)
            .where(UserModel.roles.contains([role]))
            .offset(skip)
            .limit(limit)
            .order_by(UserModel.email)
        )
        
        user_models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in user_models]
    
    def _model_to_entity(self, model: UserModel) -> User:
        """
        Convert a database model to a domain entity.
        
        Args:
            model: Database model
            
        Returns:
            Domain entity
        """
        return User(
            id=model.id,
            email=model.email,
            first_name=model.first_name,
            last_name=model.last_name,
            hashed_password=model.hashed_password,
            is_active=model.is_active,
            roles=model.roles,
            created_at=model.created_at,
            updated_at=model.updated_at
        )


async def get_user_repository(session: DBSessionDep) -> UserRepository:
    """
    Factory function to create a user repository.
    
    This function is used as a FastAPI dependency to get a user repository.
    
    Args:
        session: SQLAlchemy async session (with custom type annotation)
        
    Returns:
        UserRepository implementation
    """
    return SqlAlchemyUserRepository(session=session)