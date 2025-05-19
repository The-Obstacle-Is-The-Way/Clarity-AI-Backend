"""
Base SQLAlchemy repository implementation.

This module provides a foundational repository implementation using SQLAlchemy ORM,
following domain-driven design principles and HIPAA-compliant data access patterns.
"""

from typing import Any, Generic, TypeVar

from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.exceptions import RepositoryError
from app.infrastructure.logging.logger import get_logger

# Type variables for entity mapping
EntityT = TypeVar("EntityT")  # Domain entity
ModelT = TypeVar("ModelT")  # SQLAlchemy model

logger = get_logger(__name__)


class BaseSQLAlchemyRepository(Generic[EntityT, ModelT]):
    """
    Base repository implementation for SQLAlchemy ORM models.

    Provides common CRUD operations and mapping between domain entities and ORM models.
    """

    def __init__(self, session: AsyncSession, model_class: type[ModelT]):
        """
        Initialize the repository with a session and model class.

        Args:
            session: SQLAlchemy async session
            model_class: SQLAlchemy model class
        """
        self._session = session
        self._model_class = model_class

    async def add(self, entity: EntityT) -> EntityT:
        """
        Add a new entity to the repository.

        Args:
            entity: Domain entity to add

        Returns:
            The added entity with updated ID

        Raises:
            RepositoryError: If database operation fails
        """
        try:
            # Convert domain entity to ORM model
            model = self._to_model(entity)

            # Add to session
            self._session.add(model)

            # Flush to get the ID without committing
            await self._session.flush()

            # Convert back to domain entity with generated ID
            return self._to_entity(model)
        except SQLAlchemyError as e:
            logger.error(f"Error adding entity: {e}")
            raise RepositoryError(f"Failed to add entity: {e!s}") from e

    async def get_by_id(self, entity_id: Any) -> EntityT | None:
        """
        Get an entity by its ID.

        Args:
            entity_id: ID of the entity to retrieve

        Returns:
            The entity if found, None otherwise

        Raises:
            RepositoryError: If database operation fails
        """
        try:
            # Query the database
            query = select(self._model_class).where(self._model_class.id == entity_id)
            result = await self._session.execute(query)
            model = result.scalars().first()

            # Convert to domain entity if found
            if model:
                return self._to_entity(model)
            return None
        except SQLAlchemyError as e:
            logger.error(f"Error getting entity by ID: {e}")
            raise RepositoryError(f"Failed to get entity by ID: {e!s}") from e

    async def get_all(self) -> list[EntityT]:
        """
        Get all entities.

        Returns:
            List of all entities

        Raises:
            RepositoryError: If database operation fails
        """
        try:
            query = select(self._model_class)
            result = await self._session.execute(query)
            models = result.scalars().all()

            # Convert models to domain entities
            return [self._to_entity(model) for model in models]
        except SQLAlchemyError as e:
            logger.error(f"Error getting all entities: {e}")
            raise RepositoryError(f"Failed to get all entities: {e!s}") from e

    async def update(self, entity: EntityT) -> EntityT:
        """
        Update an existing entity.

        Args:
            entity: Domain entity to update

        Returns:
            The updated entity

        Raises:
            RepositoryError: If database operation fails
        """
        try:
            # Convert domain entity to ORM model
            model = self._to_model(entity)

            # Merge with session
            merged_model = await self._session.merge(model)

            # Flush changes
            await self._session.flush()

            # Convert back to domain entity
            return self._to_entity(merged_model)
        except SQLAlchemyError as e:
            logger.error(f"Error updating entity: {e}")
            raise RepositoryError(f"Failed to update entity: {e!s}") from e

    async def delete(self, entity_id: Any) -> bool:
        """
        Delete an entity by its ID.

        Args:
            entity_id: ID of the entity to delete

        Returns:
            True if the entity was deleted, False otherwise

        Raises:
            RepositoryError: If database operation fails
        """
        try:
            # Delete the entity
            query = delete(self._model_class).where(self._model_class.id == entity_id)
            result = await self._session.execute(query)

            # Flush changes
            await self._session.flush()

            # Check if any rows were deleted
            return result.rowcount > 0
        except SQLAlchemyError as e:
            logger.error(f"Error deleting entity: {e}")
            raise RepositoryError(f"Failed to delete entity: {e!s}") from e

    async def count(self) -> int:
        """
        Count all entities.

        Returns:
            Total count of entities

        Raises:
            RepositoryError: If database operation fails
        """
        try:
            query = select(func.count()).select_from(self._model_class)
            result = await self._session.execute(query)
            return result.scalar() or 0
        except SQLAlchemyError as e:
            logger.error(f"Error counting entities: {e}")
            raise RepositoryError(f"Failed to count entities: {e!s}") from e

    def _to_model(self, entity: EntityT) -> ModelT:
        """
        Convert a domain entity to an ORM model.

        Args:
            entity: Domain entity to convert

        Returns:
            SQLAlchemy ORM model

        Raises:
            NotImplementedError: Must be implemented by derived classes
        """
        raise NotImplementedError("Repository must implement _to_model")

    def _to_entity(self, model: ModelT) -> EntityT:
        """
        Convert an ORM model to a domain entity.

        Args:
            model: SQLAlchemy ORM model to convert

        Returns:
            Domain entity

        Raises:
            NotImplementedError: Must be implemented by derived classes
        """
        raise NotImplementedError("Repository must implement _to_entity")
