"""
User repository implementation using SQLAlchemy.

This module implements the UserRepository interface for persisting and retrieving
User entities using SQLAlchemy ORM, following clean architecture principles.

ARCHITECTURAL NOTE: This is the canonical SQLAlchemy implementation of the UserRepository.
All other implementations should be considered deprecated.
"""

import logging
import uuid

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# Domain imports
from app.domain.entities.user import User as DomainUser
from app.domain.repositories.user_repository import UserRepository as UserRepositoryInterface
from app.domain.utils.datetime_utils import now_utc
from app.infrastructure.persistence.sqlalchemy.mappers.user_mapper import UserMapper

# Infrastructure imports
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel
from app.infrastructure.persistence.sqlalchemy.models.user import UserRole

logger = logging.getLogger(__name__)


class SQLAlchemyUserRepository(UserRepositoryInterface):
    """
    SQLAlchemy implementation of the UserRepository interface.
    
    This class bridges between the domain User entity and the SQLAlchemy User model.
    It follows the Repository pattern from Domain-Driven Design, providing a collection-like
    interface for domain entities while abstracting the persistence details.
    """
    
    def __init__(self, db_session: AsyncSession):
        """
        Initialize the UserRepository with a SQLAlchemy session.
        
        Args:
            db_session: The SQLAlchemy async session to use for database operations
        """
        self._db_session = db_session
        # Implement these methods to make the interface concrete
        self._mapper = UserMapper()
    
    async def create(self, user: DomainUser) -> DomainUser:
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
            # Convert domain entity to model using the mapper
            user_model = UserMapper.to_persistence(user)
            
            # Set audit timestamps if not already set
            if not user_model.created_at:
                user_model.created_at = now_utc()
            user_model.updated_at = now_utc()
            
            # Persist to database
            self._db_session.add(user_model)
            await self._db_session.flush()
            await self._db_session.refresh(user_model)
            
            # Convert back to domain entity using the mapper
            return UserMapper.to_domain(user_model)
        except IntegrityError as e:
            logger.error(f"Integrity error when creating user: {e}")
            await self._db_session.rollback()
            raise
        except SQLAlchemyError as e:
            logger.error(f"Database error when creating user: {e}")
            await self._db_session.rollback()
            raise
    
    async def get_by_id(self, user_id: str | uuid.UUID) -> DomainUser | None:
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
            
            # Convert to domain entity using the mapper
            if user_model:
                return UserMapper.to_domain(user_model)
            return None
        except (SQLAlchemyError, ValueError) as e:
            logger.error(f"Error retrieving user by ID {user_id}: {e}")
            raise
    
    async def get_by_username(self, username: str) -> DomainUser | None:
        """
        Retrieve a user by their username.
        
        Args:
            username: The username to look up
            
        Returns:
            The User domain entity, or None if not found
        """
        try:
            # Create and execute query
            stmt = select(UserModel).where(UserModel.username == username)
            result = await self._db_session.execute(stmt)
            user_model = result.scalars().first()
            
            # Convert to domain entity using the mapper
            if user_model:
                return UserMapper.to_domain(user_model)
            return None
        except SQLAlchemyError as e:
            logger.error(f"Database error when retrieving user by username {username}: {e}")
            raise
    
    async def get_by_email(self, email: str) -> DomainUser | None:
        """
        Retrieve a user by their email address.
        
        Args:
            email: The email address to look up
            
        Returns:
            The User domain entity, or None if not found
        """
        try:
            # Prepare query
            query = select(UserModel).where(UserModel.email == email)
            
            # Execute query
            result = await self._db_session.execute(query)
            user_model = result.scalars().first()
            
            # Convert to domain entity using the mapper
            if user_model:
                return UserMapper.to_domain(user_model)
            return None
        except SQLAlchemyError as e:
            logger.error(f"Database error when retrieving user by email {email}: {e}")
            raise
    
    async def update(self, user: DomainUser) -> DomainUser:
        """
        Update an existing user in the database.
        
        Args:
            user: The domain User entity with updated data
            
        Returns:
            The updated User domain entity
            
        Raises:
            SQLAlchemyError: If there's an error during database operations
            IntegrityError: If there's a constraint violation
            ValueError: If the user doesn't exist
        """
        try:
            # Get existing model to update
            user_id = user.id
            if isinstance(user_id, str):
                user_id = uuid.UUID(user_id)
                
            existing_model = await self._db_session.get(UserModel, user_id)
            if not existing_model:
                raise ValueError(f"User with ID {user.id} not found")
            
            # Apply updates using the mapper's update method
            updated_model = UserMapper.update_persistence_model(existing_model, user)
            updated_model.updated_at = now_utc()
            
            # Persist changes
            await self._db_session.flush()
            await self._db_session.refresh(updated_model)
            
            # Convert back to domain entity using the mapper
            return UserMapper.to_domain(updated_model)
        except IntegrityError as e:
            logger.error(f"Integrity error when updating user: {e}")
            await self._db_session.rollback()
            raise
        except SQLAlchemyError as e:
            logger.error(f"Database error when updating user: {e}")
            await self._db_session.rollback()
            raise
    
    async def delete(self, user_id: str | uuid.UUID) -> bool:
        """
        Delete a user from the database.
        
        Args:
            user_id: The ID of the user to delete
            
        Returns:
            True if the user was deleted, False if not found
            
        Raises:
            SQLAlchemyError: If there's an error during database operations
        """
        try:
            # Convert string ID to UUID if necessary
            if isinstance(user_id, str):
                user_id = uuid.UUID(user_id)
            
            # Check if user exists
            user_model = await self._db_session.get(UserModel, user_id)
            if not user_model:
                return False
            
            # Delete user
            await self._db_session.delete(user_model)
            await self._db_session.flush()
            
            return True
        except SQLAlchemyError as e:
            logger.error(f"Database error when deleting user: {e}")
            await self._db_session.rollback()
            raise
    
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[DomainUser]:
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
            
            # Convert models to domain entities using the mapper
            return [UserMapper.to_domain(model) for model in user_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error when listing users: {e}")
            raise
            
    # Maintain backward compatibility with existing code that might call list_users
    async def list_users(self, skip: int = 0, limit: int = 100) -> list[DomainUser]:
        """Alias for list_all to maintain backward compatibility."""
        return await self.list_all(skip, limit)
            
    async def get_by_role(self, role: str, skip: int = 0, limit: int = 100) -> list[DomainUser]:
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
            
            # Convert to domain entities using the mapper for consistency
            return [UserMapper.to_domain(model) for model in user_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error when retrieving users by role {role}: {e}")
            raise
    
    async def _to_model(self, user: DomainUser) -> UserModel:
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
    
    async def _update_model_from_domain(self, model: UserModel, user: DomainUser) -> UserModel:
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
    
    # Helper method to convert a model to domain entity
    # This should use the mapper for consistency
    async def _to_domain(self, model: UserModel) -> DomainUser:
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
        return DomainUser(**user_data)


# For backward compatibility - provide the old name as an alias
# This allows existing code to continue working with our refactored implementation
UserRepository = SQLAlchemyUserRepository
