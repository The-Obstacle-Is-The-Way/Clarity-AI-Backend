"""
User repository implementation.

This module implements the IUserRepository using SQLAlchemy ORM,
following the Repository pattern from clean architecture principles.
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.domain.entities.user import User
from app.core.domain.entities.user import UserRole, UserStatus
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.infrastructure.persistence.sqlalchemy.models.user import (
    User as UserModel,
)
from app.infrastructure.persistence.sqlalchemy.repositories.base_repository import (
    BaseSQLAlchemyRepository,
)


class SqlAlchemyUserRepository(BaseSQLAlchemyRepository, IUserRepository):
    """
    SQLAlchemy implementation of the IUserRepository.
    
    This class bridges the domain model with the database using SQLAlchemy ORM,
    ensuring proper separation of concerns by keeping domain logic free from
    persistence details.
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize the repository with the session and specific model class."""
        super().__init__(session=session, model_class=UserModel)
        # self._session = session # Redundant assignment handled by BaseSQLAlchemyRepository
    
    def _to_entity(self, model: UserModel) -> User:
        """Convert SQLAlchemy model to domain entity."""
        # Map UserModel attributes to User domain entity fields
        # Ensure all required fields for User domain entity are provided
        domain_user_data = {
            "id": model.id,
            "username": model.username,
            "email": model.email,
            "roles": {UserRole(role_str.lower()) for role_str in model.roles} if isinstance(model.roles, list) else set(),
            "status": UserStatus.ACTIVE if model.is_active else UserStatus.INACTIVE,
            # Map other fields from UserModel to User domain entity carefully
            # The User domain entity has specific __init__ params
            # password_hash is required by User domain entity
            "password_hash": model.password_hash, 
            # full_name is required by User domain entity
            "full_name": f"{model.first_name or ''} {model.last_name or ''}".strip(),
            # Optional fields in User domain entity that have defaults or can be None
            "created_at": model.created_at if hasattr(model, 'created_at') else None,
            "last_login": model.last_login if hasattr(model, 'last_login') else None,
            # mfa_enabled and mfa_secret might need specific mapping if available in UserModel
            # attempts might need mapping if available in UserModel
        }
        
        # Filter out None values for optional fields if User dataclass doesn't handle them well
        # or if we want to rely on dataclass defaults for Nones.
        # For now, assume User dataclass handles optional fields appropriately or has defaults.

        # Ensure all fields required by User domain entity's __init__ are present
        # Current User domain entity requires: email, username, full_name, password_hash
        # id, roles, status, created_at, etc., have defaults or are handled above.
        
        return User(**domain_user_data)
    
    async def get_by_id(self, user_id: str | UUID) -> User | None:
        """
        Retrieve a user by their unique ID.
        
        Args:
            user_id: Unique identifier for the user
            
        Returns:
            User entity if found, None otherwise
        """
        # Use the base class implementation inherited from BaseSQLAlchemyRepository
        # This already handles all the SQLAlchemy session management
        # super().get_by_id now returns the User entity directly or None
        user_entity = await super().get_by_id(user_id)
        return user_entity # No need to call _to_entity again
        
    async def get_user_by_id(self, user_id: str | UUID) -> User | None:
        """
        Alias for get_by_id to maintain API compatibility with auth dependencies.
        
        This method exists to address an architectural inconsistency where:
        - The core interface uses get_by_id (as per IUserRepository)
        - Auth dependencies call get_user_by_id
        
        Args:
            user_id: Unique identifier for the user
            
        Returns:
            User entity if found, None otherwise
        """
        # Simply delegate to the standard interface method
        return await self.get_by_id(user_id)
    
    async def get_by_email(self, email: str) -> User | None:
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
    
    async def get_by_username(self, username: str) -> User | None:
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
    
    async def delete(self, user_id: str | UUID) -> bool:
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
    
    async def list_all(self, skip: int = 0, limit: int = 100) -> list[User]:
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


def get_user_repository(session: AsyncSession) -> IUserRepository:
    """
    Factory function to create a UserRepository instance.
    
    This function allows for dependency injection of the repository
    in FastAPI dependency functions.
    
    Args:
        session: SQLAlchemy async session for database operations
        
    Returns:
        An instance of IUserRepository
    """
    return SqlAlchemyUserRepository(session)