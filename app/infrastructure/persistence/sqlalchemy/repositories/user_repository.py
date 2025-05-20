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
from sqlalchemy.future import select

# Domain imports
from app.core.domain.entities.user import User as DomainUser
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

    def __init__(self, session_factory=None, db_session=None):
        """
        Initialize the UserRepository with a SQLAlchemy session factory or session.

        Args:
            session_factory: The SQLAlchemy async session factory to create sessions.
            db_session: Direct session object (for backward compatibility, will be deprecated).

        Raises:
            ValueError: If neither session_factory nor db_session is provided.
        """
        if session_factory is not None:
            self._session_factory = session_factory
            self._external_session = None
        elif db_session is not None:
            logger.warning(
                "Initializing SQLAlchemyUserRepository with db_session is deprecated. Use session_factory instead."
            )
            self._session_factory = None
            self._external_session = db_session
        else:
            raise ValueError("Either session_factory or db_session must be provided")

        self._mapper = UserMapper()

    async def _get_session(self):
        """
        Get a session for database operations.

        Returns:
            A session object, either from the factory or the external session.

        Note:
            If using an external session, the caller is responsible for committing or rolling back.
        """
        if self._session_factory is not None:
            return self._session_factory()
        return self._external_session

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
        session = await self._get_session()

        # If using session factory, we'll manage the session
        if self._session_factory is not None:
            async with session as session:
                try:
                    user_model = UserMapper.to_persistence(user)
                    if not user_model.created_at:
                        user_model.created_at = now_utc()
                    user_model.updated_at = now_utc()

                    session.add(user_model)
                    await session.flush()
                    await session.refresh(user_model)
                    return UserMapper.to_domain(user_model)
                except IntegrityError as e:
                    logger.error(f"Integrity error when creating user: {e}")
                    await session.rollback()
                    raise
                except SQLAlchemyError as e:
                    logger.error(f"Database error when creating user: {e}")
                    await session.rollback()
                    raise
        else:
            # Using external session - don't manage it here
            try:
                user_model = UserMapper.to_persistence(user)
                if not user_model.created_at:
                    user_model.created_at = now_utc()
                user_model.updated_at = now_utc()

                session.add(user_model)
                await session.flush()
                await session.refresh(user_model)
                return UserMapper.to_domain(user_model)
            except (IntegrityError, SQLAlchemyError) as e:
                logger.error(f"Database error when creating user: {e}")
                raise

    async def get_by_id(self, user_id: str | uuid.UUID) -> DomainUser | None:
        """
        Retrieve a user by their ID.

        Args:
            user_id: The ID of the user to retrieve

        Returns:
            The User domain entity, or None if not found
        """
        session = await self._get_session()

        # If using session factory, we'll manage the session
        if self._session_factory is not None:
            async with session as session:
                try:
                    if isinstance(user_id, str):
                        user_id = uuid.UUID(user_id)

                    user_model = await session.get(UserModel, user_id)

                    if not user_model:
                        logger.warning(f"User with id {user_id} not found")
                        return None

                    return UserMapper.to_domain(user_model)
                except SQLAlchemyError as e:
                    logger.error(f"Error retrieving user by id: {e}")
                    return None
        else:
            # Using external session - don't manage it here
            try:
                if isinstance(user_id, str):
                    user_id = uuid.UUID(user_id)

                user_model = await session.get(UserModel, user_id)

                if not user_model:
                    logger.warning(f"User with id {user_id} not found")
                    return None

                return UserMapper.to_domain(user_model)
            except SQLAlchemyError as e:
                logger.error(f"Error retrieving user by id: {e}")
                return None

    async def get_user_by_id(self, user_id: str | uuid.UUID) -> DomainUser | None:
        """
        Alias for get_by_id to maintain API compatibility with auth dependencies.

        This method exists to address an architectural inconsistency where:
        - The core interface uses get_by_id (as per IUserRepository)
        - Auth dependencies call get_user_by_id

        Args:
            user_id: The ID of the user to retrieve

        Returns:
            The User domain entity if found, None otherwise
        """
        return await self.get_by_id(user_id)

    async def get_by_username(self, username: str) -> DomainUser | None:
        """
        Retrieve a user by their username.

        Args:
            username: The username to look up

        Returns:
            The User domain entity, or None if not found
        """
        session = await self._get_session()
        async with session as session:
            try:
                # Create and execute query
                stmt = select(UserModel).where(UserModel.username == username)
                result = await session.execute(stmt)
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
        session = await self._get_session()
        async with session as session:
            try:
                # Prepare query
                query = select(UserModel).where(UserModel.email == email)

                # Execute query
                result = await session.execute(query)
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
        session = await self._get_session()
        async with session as session:
            try:
                # Get existing model to update
                user_id = user.id
                if isinstance(user_id, str):
                    user_id = uuid.UUID(user_id)

                existing_model = await session.get(UserModel, user_id)
                if not existing_model:
                    raise ValueError(f"User with ID {user.id} not found")

                # Apply updates using the mapper's update method
                updated_model = UserMapper.update_persistence_model(existing_model, user)
                updated_model.updated_at = now_utc()

                # Persist changes
                await session.flush()
                await session.refresh(updated_model)

                # Convert back to domain entity using the mapper
                return UserMapper.to_domain(updated_model)
            except IntegrityError as e:
                logger.error(f"Integrity error when updating user: {e}")
                await session.rollback()
                raise
            except SQLAlchemyError as e:
                logger.error(f"Database error when updating user: {e}")
                await session.rollback()
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
        session = await self._get_session()
        async with session as session:
            try:
                # Convert string ID to UUID if necessary
                if isinstance(user_id, str):
                    user_id = uuid.UUID(user_id)

                # Check if user exists
                user_model = await session.get(UserModel, user_id)
                if not user_model:
                    return False

                # Delete user
                await session.delete(user_model)
                await session.flush()

                return True
            except SQLAlchemyError as e:
                logger.error(f"Database error when deleting user: {e}")
                await session.rollback()
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
        session = await self._get_session()
        async with session as session:
            try:
                # Prepare query
                query = select(UserModel).offset(skip).limit(limit)

                # Execute query
                result = await session.execute(query)
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
        session = await self._get_session()
        async with session as session:
            try:
                # Try to convert role string to UserRole enum
                try:
                    role_enum = UserRole(role)
                    # Prepare query with enum
                    query = (
                        select(UserModel)
                        .where(UserModel.role == role_enum)
                        .offset(skip)
                        .limit(limit)
                    )
                except ValueError:
                    # If role is not in UserRole enum, return empty list
                    logger.warning(f"Role {role} not found in UserRole enum")
                    return []

                # Execute query
                result = await session.execute(query)
                user_models = result.scalars().all()

                # Convert to domain entities using the mapper for consistency
                return [UserMapper.to_domain(model) for model in user_models]
            except SQLAlchemyError as e:
                logger.error(f"Database error when retrieving users by role {role}: {e}")
                raise

    async def count(self) -> int:
        """
        Count the total number of users.

        Returns:
            The total number of users in the repository
        """
        from sqlalchemy import func  # Import func for count

        session = await self._get_session()
        async with session as session:
            try:
                stmt = select(func.count()).select_from(UserModel)
                result = await session.execute(stmt)
                count = result.scalar_one_or_none()
                return count if count is not None else 0
            except SQLAlchemyError as e:
                logger.error(f"Database error when counting users: {e}")
                raise

    async def exists(self, user_id: uuid.UUID) -> bool:
        """
        Check if a user exists by their ID.

        Args:
            user_id: The UUID of the user to check

        Returns:
            True if the user exists, False otherwise
        """
        from sqlalchemy import func  # Import func for count

        session = await self._get_session()
        async with session as session:
            try:
                stmt = select(func.count(UserModel.id)).where(UserModel.id == user_id)
                result = await session.execute(stmt)
                count = result.scalar_one_or_none()
                return (count if count is not None else 0) > 0
            except SQLAlchemyError as e:
                logger.error(f"Database error when checking if user exists by ID {user_id}: {e}")
                raise

    async def exists_by_email(self, email: str) -> bool:
        """
        Check if a user exists by their email.

        Args:
            email: The email address to check

        Returns:
            True if a user with the given email exists, False otherwise
        """
        from sqlalchemy import func  # Import func for count

        session = await self._get_session()
        async with session as session:
            try:
                stmt = select(func.count(UserModel.id)).where(UserModel.email == email)
                result = await session.execute(stmt)
                count = result.scalar_one_or_none()
                return (count if count is not None else 0) > 0
            except SQLAlchemyError as e:
                logger.error(f"Database error when checking if user exists by email {email}: {e}")
                raise

    async def _to_model(self, user: DomainUser) -> UserModel:
        """
        Convert a User domain entity to a User model.

        This is a private helper method used internally by the repository.

        Args:
            user: The domain User entity to convert

        Returns:
            The SQLAlchemy User model
        """
        return UserMapper.to_persistence(user)


def get_user_repository(session_factory=None, db_session=None) -> SQLAlchemyUserRepository:
    """
    Factory function to create a properly configured SQLAlchemyUserRepository.

    Args:
        session_factory: The SQLAlchemy async session factory to use.
        db_session: Direct session object (for backward compatibility).

    Returns:
        A configured SQLAlchemyUserRepository instance.
    """
    if session_factory is not None:
        return SQLAlchemyUserRepository(session_factory=session_factory)
    elif db_session is not None:
        return SQLAlchemyUserRepository(db_session=db_session)
    else:
        raise ValueError("Either session_factory or db_session must be provided")


# Export aliases to maintain backward compatibility with names used in UnitOfWorkFactory
UserRepositoryImpl = SQLAlchemyUserRepository
