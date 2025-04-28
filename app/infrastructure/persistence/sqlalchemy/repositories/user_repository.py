# -*- coding: utf-8 -*-
"""
User repository implementation using SQLAlchemy.

This module implements the UserRepository class for persisting and retrieving
User entities using SQLAlchemy ORM.
"""

import uuid
from typing import List, Optional, Dict, Any, Union, cast
import logging
from datetime import datetime

from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import update, delete, and_, or_, func

from app.domain.entities.user import User as UserDomain
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel, UserRole
from app.domain.repositories.user_repository import IUserRepository
from app.domain.utils.datetime_utils import now_utc


logger = logging.getLogger(__name__)


class UserRepository(IUserRepository):
    """
    SQLAlchemy implementation of the UserRepository interface.
    
    This class bridges between the domain User entity and the SQLAlchemy User model.
    """
    
    def __init__(self, db_session: AsyncSession):
        """
        Initialize the UserRepository with a SQLAlchemy session.
        
        Args:
            db_session: The SQLAlchemy async session to use for database operations
        """
        self._db_session = db_session
    
    async def create(self, user: UserDomain) -> UserDomain:
        """
        Create a new user in the database.
        
        Args:
            user: The domain User entity to persist
            
        Returns:
            The created User domain entity
            
        Raises:
            SQLAlchemyError: If there's an error during database operations
            IntegrityError: If there's a constraint violation (e.g., duplicate username or email)
        """
        try:
            # Convert domain entity to model
            user_model = await self._to_model(user)
            user_model.created_at = now_utc()
            user_model.updated_at = now_utc()
            
            # Persist to database
            self._db_session.add(user_model)
            await self._db_session.flush()
            await self._db_session.refresh(user_model)
            
            # Convert back to domain entity
            return await self._to_domain(user_model)
        except IntegrityError as e:
            logger.error(f"Integrity error when creating user: {e}")
            await self._db_session.rollback()
            raise
        except SQLAlchemyError as e:
            logger.error(f"Database error when creating user: {e}")
            await self._db_session.rollback()
            raise
    
    async def get_by_id(self, user_id: Union[str, uuid.UUID]) -> Optional[UserDomain]:
        """
        Retrieve a user by their ID.
        
        Args:
            user_id: The ID of the user to retrieve
            
        Returns:
            The User domain entity, or None if not found
        """
        try:
            # Convert string ID to UUID if necessary
            if isinstance(user_id, str):
                user_id = uuid.UUID(user_id)
            
            # Query the database
            user_model = await self._db_session.get(UserModel, user_id)
            
            if not user_model:
                return None
            
            return await self._to_domain(user_model)
        except SQLAlchemyError as e:
            logger.error(f"Database error when retrieving user by ID {user_id}: {e}")
            raise
    
    async def get_by_username(self, username: str) -> Optional[UserDomain]:
        """
        Retrieve a user by their username.
        
        Args:
            username: The username of the user to retrieve
            
        Returns:
            The User domain entity, or None if not found
        """
        try:
            # Prepare query
            query = select(UserModel).where(UserModel.username == username)
            
            # Execute query
            result = await self._db_session.execute(query)
            user_model = result.scalars().first()
            
            if not user_model:
                return None
            
            return await self._to_domain(user_model)
        except SQLAlchemyError as e:
            logger.error(f"Database error when retrieving user by username {username}: {e}")
            raise
    
    async def get_by_email(self, email: str) -> Optional[UserDomain]:
        """
        Retrieve a user by their email address.
        
        Args:
            email: The email of the user to retrieve
            
        Returns:
            The User domain entity, or None if not found
        """
        try:
            # Prepare query
            query = select(UserModel).where(UserModel.email == email)
            
            # Execute query
            result = await self._db_session.execute(query)
            user_model = result.scalars().first()
            
            if not user_model:
                return None
            
            return await self._to_domain(user_model)
        except SQLAlchemyError as e:
            logger.error(f"Database error when retrieving user by email {email}: {e}")
            raise
    
    async def update(self, user: UserDomain) -> UserDomain:
        """
        Update an existing user in the database.
        
        Args:
            user: The domain User entity with updated data
            
        Returns:
            The updated User domain entity
            
        Raises:
            SQLAlchemyError: If there's an error during database operations
            IntegrityError: If there's a constraint violation (e.g., duplicate username or email)
        """
        try:
            # Retrieve existing user model
            user_id = user.id
            if isinstance(user_id, str):
                user_id = uuid.UUID(user_id)
            
            user_model = await self._db_session.get(UserModel, user_id)
            
            if not user_model:
                raise ValueError(f"User with ID {user_id} not found")
            
            # Update model with domain entity data
            updated_model = await self._update_model_from_domain(user_model, user)
            updated_model.updated_at = now_utc()
            
            # Persist changes
            await self._db_session.flush()
            await self._db_session.refresh(updated_model)
            
            # Convert back to domain entity
            return await self._to_domain(updated_model)
        except IntegrityError as e:
            logger.error(f"Integrity error when updating user: {e}")
            await self._db_session.rollback()
            raise
        except SQLAlchemyError as e:
            logger.error(f"Database error when updating user: {e}")
            await self._db_session.rollback()
            raise
    
    async def delete(self, user_id: Union[str, uuid.UUID]) -> bool:
        """
        Delete a user from the database.
        
        Args:
            user_id: The ID of the user to delete
            
        Returns:
            True if the user was deleted, False if not found
        """
        try:
            # Convert string ID to UUID if necessary
            if isinstance(user_id, str):
                user_id = uuid.UUID(user_id)
            
            # Query the database
            user_model = await self._db_session.get(UserModel, user_id)
            
            if not user_model:
                return False
            
            # Delete the user
            await self._db_session.delete(user_model)
            await self._db_session.flush()
            
            return True
        except SQLAlchemyError as e:
            logger.error(f"Database error when deleting user {user_id}: {e}")
            await self._db_session.rollback()
            raise
    
    async def list_users(self, skip: int = 0, limit: int = 100) -> List[UserDomain]:
        """
        Retrieve a list of users from the database.
        
        Args:
            skip: Number of records to skip for pagination
            limit: Maximum number of records to return
            
        Returns:
            List of User domain entities
        """
        try:
            # Prepare query
            query = select(UserModel).offset(skip).limit(limit)
            
            # Execute query
            result = await self._db_session.execute(query)
            user_models = result.scalars().all()
            
            # Convert to domain entities
            return [await self._to_domain(model) for model in user_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error when listing users: {e}")
            raise
            
    async def get_by_role(self, role: str, skip: int = 0, limit: int = 100) -> List[UserDomain]:
        """
        Get users by role.
        
        Args:
            role: Role to filter by
            skip: Number of users to skip
            limit: Maximum number of users to return
            
        Returns:
            List of users with the specified role
        """
        try:
            # Try to convert role string to UserRole enum
            try:
                role_enum = UserRole(role)
                # Prepare query with enum
                query = select(UserModel).where(UserModel.role == role_enum).offset(skip).limit(limit)
            except ValueError:
                # If role is not in UserRole enum, return empty list
                logger.warning(f"Role {role} not found in UserRole enum")
                return []
            
            # Execute query
            result = await self._db_session.execute(query)
            user_models = result.scalars().all()
            
            # Convert to domain entities
            return [await self._to_domain(model) for model in user_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error when retrieving users by role {role}: {e}")
            raise
    
    async def _to_model(self, user: UserDomain) -> UserModel:
        """
        Convert a User domain entity to a User model.
        
        Args:
            user: The domain User entity to convert
            
        Returns:
            The SQLAlchemy User model
        """
        # Convert domain entity to model
        user_model = UserModel()
        
        # Set ID if it exists, otherwise it will be generated
        if user.id:
            if isinstance(user.id, str):
                user_model.id = uuid.UUID(user.id)
            else:
                user_model.id = user.id
        
        # Core fields
        user_model.username = user.username
        user_model.email = user.email
        user_model.password_hash = user.hashed_password
        user_model.is_active = user.is_active
        user_model.is_verified = getattr(user, 'is_verified', False)
        user_model.email_verified = getattr(user, 'email_verified', False)
        
        # Handle role - convert from domain to infrastructure
        if hasattr(user, 'role') and user.role:
            try:
                user_model.role = UserRole(user.role)
            except ValueError:
                # Default to patient role if conversion fails
                user_model.role = UserRole.PATIENT
                logger.warning(f"Invalid role {user.role} defaulted to PATIENT")
        elif user.roles:
            # Try to get role from roles list
            for role in user.roles:
                try:
                    user_model.role = UserRole(role)
                    break
                except ValueError:
                    continue
            # Default if no valid role found
            if not user_model.role:
                user_model.role = UserRole.PATIENT
                
        # Profile fields
        user_model.first_name = getattr(user, 'first_name', None)
        user_model.last_name = getattr(user, 'last_name', None)
        
        # Additional fields if they exist in the domain entity
        if hasattr(user, 'failed_login_attempts'):
            user_model.failed_login_attempts = user.failed_login_attempts
            
        if hasattr(user, 'account_locked_until'):
            user_model.account_locked_until = user.account_locked_until
            
        if hasattr(user, 'password_changed_at'):
            user_model.password_changed_at = user.password_changed_at
            
        if hasattr(user, 'last_login'):
            user_model.last_login = user.last_login
            
        if hasattr(user, 'preferences') and user.preferences:
            user_model.preferences = user.preferences
            
        return user_model
    
    async def _update_model_from_domain(self, model: UserModel, user: UserDomain) -> UserModel:
        """
        Update an existing User model with data from a domain entity.
        
        Args:
            model: The existing SQLAlchemy User model
            user: The domain User entity with updated data
            
        Returns:
            The updated SQLAlchemy User model
        """
        # Update core fields
        if hasattr(user, 'username') and user.username is not None:
            model.username = user.username
            
        if hasattr(user, 'email') and user.email is not None:
            model.email = user.email
            
        if hasattr(user, 'hashed_password') and user.hashed_password is not None:
            model.password_hash = user.hashed_password
            model.password_changed_at = now_utc()
            
        if hasattr(user, 'is_active'):
            model.is_active = user.is_active
            
        if hasattr(user, 'is_verified'):
            model.is_verified = user.is_verified
            
        if hasattr(user, 'email_verified'):
            model.email_verified = user.email_verified
            
        # Handle role - convert from domain to infrastructure
        if hasattr(user, 'role') and user.role:
            try:
                model.role = UserRole(user.role)
            except ValueError:
                logger.warning(f"Invalid role {user.role} not updated")
        elif hasattr(user, 'roles') and user.roles:
            # Try to get role from roles list
            for role in user.roles:
                try:
                    model.role = UserRole(role)
                    break
                except ValueError:
                    continue
                
        # Profile fields
        if hasattr(user, 'first_name'):
            model.first_name = user.first_name
            
        if hasattr(user, 'last_name'):
            model.last_name = user.last_name
            
        # Additional fields if they exist in the domain entity
        if hasattr(user, 'failed_login_attempts'):
            model.failed_login_attempts = user.failed_login_attempts
            
        if hasattr(user, 'account_locked_until'):
            model.account_locked_until = user.account_locked_until
            
        if hasattr(user, 'last_login'):
            model.last_login = user.last_login
            
        if hasattr(user, 'preferences'):
            model.preferences = user.preferences
            
        return model
    
    async def _to_domain(self, model: UserModel) -> UserDomain:
        """
        Convert a User model to a User domain entity.
        
        Args:
            model: The SQLAlchemy User model to convert
            
        Returns:
            The User domain entity
        """
        # Create role list for backwards compatibility
        roles = [model.role.value] if model.role else []
        
        # Create domain entity with required fields
        user_data = {
            'id': str(model.id),
            'username': model.username,
            'email': model.email,
            'hashed_password': model.password_hash,
            'is_active': model.is_active,
            'roles': roles,
            'role': model.role.value if model.role else None,
            'is_verified': model.is_verified,
            'email_verified': model.email_verified,
            'failed_login_attempts': model.failed_login_attempts,
            'account_locked_until': model.account_locked_until,
            'password_changed_at': model.password_changed_at,
            'first_name': model.first_name,
            'last_name': model.last_name,
            'full_name': f"{model.first_name} {model.last_name}" if model.first_name and model.last_name else None,
            'created_at': model.created_at,
            'updated_at': model.updated_at,
            'last_login': model.last_login,
            'preferences': model.preferences
        }
        
        # Create and return domain entity
        return UserDomain(**user_data)
