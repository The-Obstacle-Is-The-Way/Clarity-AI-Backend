"""
SQLAlchemy implementation of the BiometricRuleRepository for the Novamind platform.

This module provides a concrete implementation of the BiometricRuleRepository interface
using SQLAlchemy as the ORM for database interactions. It handles the translation 
between domain entities and database models.
"""

import logging
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.interfaces.repositories.biometric_rule_repository import (
    IBiometricRuleRepository,
)
from app.domain.entities.biometric_rule import BiometricRule
from app.domain.exceptions.repository import (
    DatabaseConnectionException,
    EntityNotFoundException,
    RepositoryError,
)
from app.infrastructure.persistence.sqlalchemy.mappers.biometric_rule_mapper import (
    map_rule_entity_to_model,
    map_rule_model_to_entity,
)
from app.infrastructure.persistence.sqlalchemy.models.biometric_rule import (
    BiometricRuleModel,
)

logger = logging.getLogger(__name__)


class SQLAlchemyBiometricRuleRepository(IBiometricRuleRepository):
    """SQLAlchemy implementation of the BiometricRuleRepository."""

    def __init__(self, session: AsyncSession):
        """
        Initialize the repository with a database session.

        Args:
            session: SQLAlchemy async session for database operations
        """
        self.session = session

    async def create(self, rule: BiometricRule) -> BiometricRule:
        """Create a new BiometricRule entity in the database."""
        rule_model = map_rule_entity_to_model(rule)
        try:
            self.session.add(rule_model)
            await self.session.commit()
            await self.session.refresh(rule_model)
            return map_rule_model_to_entity(rule_model)
        except IntegrityError as e:
            await self.session.rollback()
            logger.error(f"Database error creating biometric rule {rule.id}: {e}")
            raise DatabaseConnectionException(f"Database error creating rule: {e!s}") from e
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Unexpected error creating biometric rule {rule.id}: {e}")
            raise RepositoryError(f"Unexpected error creating rule: {e!s}") from e

    async def get_by_id(self, rule_id: UUID) -> BiometricRule | None:
        """Retrieve a BiometricRule entity by its ID."""
        try:
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.id == rule_id)
            result = await self.session.execute(stmt)
            rule_model = result.scalar_one_or_none()
            if not rule_model:
                return None
            return map_rule_model_to_entity(rule_model)
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving rule {rule_id}: {e}")
            raise DatabaseConnectionException(
                f"Database error retrieving rule {rule_id}: {e!s}"
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving rule {rule_id}: {e}")
            raise RepositoryError(f"Unexpected error retrieving rule {rule_id}: {e!s}") from e

    async def get_by_patient_id(
        self, patient_id: UUID, limit: int = 100, skip: int = 0
    ) -> list[BiometricRule]:
        """Retrieve biometric rules for a specific patient."""
        try:
            stmt = (
                select(BiometricRuleModel)
                .where(BiometricRuleModel.patient_id == patient_id)
                .offset(skip)
                .limit(limit)
            )
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving rules for patient {patient_id}: {e}")
            raise DatabaseConnectionException(
                f"Database error retrieving rules for patient {patient_id}: {e!s}"
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving rules for patient {patient_id}: {e}")
            raise RepositoryError(
                f"Unexpected error retrieving rules for patient {patient_id}: {e!s}"
            ) from e

    async def list_all(self, skip: int = 0, limit: int = 100) -> list[BiometricRule]:
        """List all biometric rules with pagination."""
        try:
            stmt = select(BiometricRuleModel).offset(skip).limit(limit)
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving all rules: {e}")
            raise DatabaseConnectionException(f"Database error retrieving all rules: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving all rules: {e}")
            raise RepositoryError(f"Unexpected error retrieving all rules: {e!s}") from e

    async def update(self, rule: BiometricRule) -> BiometricRule:
        """Update an existing BiometricRule entity in the database."""
        if not rule.id:
            logger.error("Attempted to update a rule without an ID.")
            raise ValueError("Cannot update a rule without an ID.")
        try:
            # Use ORM-style update for better type safety
            rule_model = await self.session.get(BiometricRuleModel, rule.id)
            if not rule_model:
                raise EntityNotFoundException(f"Biometric rule with ID {rule.id} not found")

            # Type assertion to help mypy understand rule_model is not None after the check
            assert rule_model is not None
            updated_model = map_rule_entity_to_model(rule)
            rule_model.name = updated_model.name
            rule_model.description = updated_model.description
            rule_model.patient_id = updated_model.patient_id
            rule_model.provider_id = updated_model.provider_id
            rule_model.is_active = updated_model.is_active
            rule_model.alert_priority = updated_model.alert_priority
            rule_model.logical_operator = updated_model.logical_operator
            rule_model.conditions = updated_model.conditions
            rule_model.updated_at = updated_model.updated_at

            await self.session.commit()
            return rule
        except SQLAlchemyError as e:
            await self.session.rollback()
            logger.error(f"Database error updating rule {rule.id}: {e}")
            raise DatabaseConnectionException(f"Database error updating rule: {e!s}") from e
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Unexpected error updating rule {rule.id}: {e}")
            raise RepositoryError(f"Unexpected error updating rule: {e!s}") from e

    async def delete(self, rule_id: UUID) -> bool:
        """Delete a biometric rule record by its ID. Returns True if deletion was successful."""
        try:
            rule_model = await self.session.get(BiometricRuleModel, rule_id)
            if not rule_model:
                logger.warning(f"Attempted to delete non-existent rule with ID: {rule_id}")
                return False

            # Type assertion to help mypy understand rule_model is not None after the check
            assert rule_model is not None
            await self.session.delete(rule_model)
            await self.session.commit()
            logger.info(f"Successfully deleted rule with ID: {rule_id}")
            return True
        except SQLAlchemyError as e:
            await self.session.rollback()
            logger.error(f"Database error deleting rule {rule_id}: {e}")
            raise DatabaseConnectionException(
                f"Database error deleting rule {rule_id}: {e!s}"
            ) from e
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Unexpected error deleting rule {rule_id}: {e}")
            raise RepositoryError(f"Unexpected error deleting rule {rule_id}: {e!s}") from e

    async def get_active_rules(self, patient_id: UUID | None = None) -> list[BiometricRule]:
        """Retrieve active (enabled) rules, optionally filtered by patient."""
        try:
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.is_active)
            if patient_id is not None:
                stmt = stmt.where(BiometricRuleModel.patient_id == patient_id)

            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving active rules: {e}")
            raise DatabaseConnectionException(
                f"Database error retrieving active rules: {e!s}"
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving active rules: {e}")
            raise RepositoryError(f"Unexpected error retrieving active rules: {e!s}") from e

    # Additional helper methods for backward compatibility and extended functionality
    async def get_by_provider_id(self, provider_id: UUID) -> list[BiometricRule]:
        """Retrieve all BiometricRules created by a specific provider."""
        try:
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.provider_id == provider_id)
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving rules for provider {provider_id}: {e}")
            raise DatabaseConnectionException(
                f"Database error retrieving rules for provider {provider_id}: {e!s}"
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving rules for provider {provider_id}: {e}")
            raise RepositoryError(
                f"Unexpected error retrieving rules for provider {provider_id}: {e!s}"
            ) from e

    async def save(self, rule: BiometricRule) -> BiometricRule:
        """Save a BiometricRule entity (create or update)."""
        try:
            if rule.id:
                logger.debug(f"Calling update for rule ID: {rule.id}")
                return await self.update(rule)
            else:
                logger.debug("Calling create for new rule.")
                return await self.create(rule)
        except EntityNotFoundException:
            logger.warning(f"Rule with ID {rule.id} not found for update, attempting to create.")
            # Create a new rule without the ID for creation
            new_rule = BiometricRule(
                name=rule.name,
                description=rule.description,
                patient_id=rule.patient_id,
                provider_id=rule.provider_id,
                is_active=rule.is_active,
                priority=rule.priority,
                conditions=rule.conditions,
                logical_operator=rule.logical_operator,
                data_type=rule.data_type,
            )
            return await self.create(new_rule)
        except (DatabaseConnectionException, RepositoryError) as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error saving rule (ID: {rule.id}): {e}")
            raise RepositoryError(f"Unexpected error saving rule: {e!s}") from e

    async def count_active_rules(self, patient_id: UUID) -> int:
        """Count the number of active rules for a patient."""
        try:
            stmt = (
                select(func.count(BiometricRuleModel.id))
                .where(BiometricRuleModel.patient_id == patient_id)
                .where(BiometricRuleModel.is_active)
            )
            result = await self.session.execute(stmt)
            count = result.scalar_one_or_none() or 0
            return count
        except SQLAlchemyError as e:
            logger.error(f"Database error counting active rules for patient {patient_id}: {e}")
            raise DatabaseConnectionException(
                f"Database error counting active rules for patient {patient_id}: {e!s}"
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error counting active rules for patient {patient_id}: {e}")
            raise RepositoryError(
                f"Unexpected error counting active rules for patient {patient_id}: {e!s}"
            ) from e

    async def update_active_status(self, rule_id: UUID, is_active: bool) -> bool:
        """Update the active status of a rule. Returns True if updated, False otherwise."""
        try:
            rule_model = await self.session.get(BiometricRuleModel, rule_id)
            if not rule_model:
                logger.warning(f"Rule with ID {rule_id} not found for status update.")
                return False

            # Type assertion to help mypy understand rule_model is not None after the check
            assert rule_model is not None
            rule_model.is_active = is_active
            await self.session.commit()
            logger.info(f"Successfully updated active status for rule {rule_id} to {is_active}")
            return True
        except SQLAlchemyError as e:
            await self.session.rollback()
            logger.error(f"Database error updating active status for rule {rule_id}: {e}")
            raise DatabaseConnectionException(
                f"Database error updating status for rule {rule_id}: {e!s}"
            ) from e
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Unexpected error updating active status for rule {rule_id}: {e}")
            raise RepositoryError(
                f"Unexpected error updating status for rule {rule_id}: {e!s}"
            ) from e


# Factory function for dependency injection
def get_biometric_rule_repository(session: AsyncSession) -> IBiometricRuleRepository:
    """Factory function to create an instance of SQLAlchemyBiometricRuleRepository."""
    logger.debug("Creating SQLAlchemyBiometricRuleRepository instance via factory.")
    return SQLAlchemyBiometricRuleRepository(session=session)


# Export alias to maintain backward compatibility with names used in UnitOfWorkFactory
BiometricRuleRepositoryImpl = SQLAlchemyBiometricRuleRepository
