"""
SQLAlchemy implementation of the BiometricRuleRepository for the Novamind platform.

This module provides a concrete implementation of the BiometricRuleRepository interface
using SQLAlchemy as the ORM for database interactions. It handles the translation 
between domain entities and database models.
"""

import logging
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.interfaces.repositories.biometric_rule_repository import IBiometricRuleRepository
from app.domain.entities.biometric_alert_rule import BiometricAlertRule
from app.domain.exceptions.repository import (
    DatabaseConnectionException,
    EntityNotFoundException,
    RepositoryError,
)
from app.infrastructure.persistence.sqlalchemy.mappers.biometric_rule_mapper import (
    map_rule_entity_to_model,
    map_rule_model_to_entity,
)
from app.infrastructure.persistence.sqlalchemy.models.biometric_rule import BiometricRuleModel

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

    async def add(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Add a new BiometricAlertRule entity to the database."""
        rule_model = map_rule_entity_to_model(rule)
        try:
            self.session.add(rule_model)
            await self.session.commit()
            await self.session.refresh(rule_model)
            return map_rule_model_to_entity(rule_model)
        except IntegrityError as e:
            await self.session.rollback()
            logger.error(f"Database error adding biometric rule {rule.id}: {e}")
            raise DatabaseConnectionException(f"Database error adding rule: {e!s}") from e
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Unexpected error adding biometric rule {rule.id}: {e}")
            raise RepositoryError(f"Unexpected error adding rule: {e!s}") from e

    async def get_by_id(self, rule_id: UUID) -> BiometricAlertRule | None:
        """Retrieve a BiometricAlertRule entity by its ID."""
        try:
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.id == rule_id)
            result = await self.session.execute(stmt)
            rule_model = result.scalar_one_or_none()
            if not rule_model:
                return None
            return map_rule_model_to_entity(rule_model)
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving rule {rule_id}: {e}")
            raise DatabaseConnectionException(f"Database error retrieving rule {rule_id}: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving rule {rule_id}: {e}")
            raise RepositoryError(f"Unexpected error retrieving rule {rule_id}: {e!s}") from e

    async def get_all(self) -> list[BiometricAlertRule]:
        """Retrieve all BiometricAlertRule entities."""
        try:
            stmt = select(BiometricRuleModel)
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving all rules: {e}")
            raise DatabaseConnectionException(f"Database error retrieving all rules: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving all rules: {e}")
            raise RepositoryError(f"Unexpected error retrieving all rules: {e!s}") from e

    async def update(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Update an existing BiometricAlertRule entity in the database."""
        if not rule.id:
            logger.error("Attempted to update a rule without an ID.")
            raise ValueError("Cannot update a rule without an ID.")
        try:
            existing_rule = await self.get_by_id(rule.id)
            if not existing_rule:
                raise EntityNotFoundException(f"Biometric rule with ID {rule.id} not found")
            rule_model = map_rule_entity_to_model(rule)
            stmt = (
                update(BiometricRuleModel)
                .where(BiometricRuleModel.id == rule.id)
                .values(**{
                    key: getattr(rule_model, key)
                    for key in rule_model.__dict__
                    if not key.startswith('_')
                })
                .execution_options(synchronize_session="fetch")
            )
            await self.session.execute(stmt)
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
        """Delete a BiometricAlertRule entity by its ID."""
        try:
            existing_rule = await self.get_by_id(rule_id)
            if not existing_rule:
                logger.warning(f"Attempted to delete non-existent rule with ID: {rule_id}")
                return False
            stmt = delete(BiometricRuleModel).where(BiometricRuleModel.id == rule_id)
            result = await self.session.execute(stmt)
            await self.session.commit()
            deleted_count = result.rowcount
            if deleted_count == 0:
                logger.warning(f"Rule with ID {rule_id} was not found for deletion, though existed moments ago.")
                return False
            logger.info(f"Successfully deleted rule with ID: {rule_id}")
            return True
        except SQLAlchemyError as e:
            await self.session.rollback()
            logger.error(f"Database error deleting rule {rule_id}: {e}")
            raise DatabaseConnectionException(f"Database error deleting rule {rule_id}: {e!s}") from e
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Unexpected error deleting rule {rule_id}: {e}")
            raise RepositoryError(f"Unexpected error deleting rule {rule_id}: {e!s}") from e

    async def get_by_patient_id(self, patient_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve all BiometricAlertRules for a specific patient."""
        try:
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.patient_id == patient_id)
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving rules for patient {patient_id}: {e}")
            raise DatabaseConnectionException(f"Database error retrieving rules for patient {patient_id}: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving rules for patient {patient_id}: {e}")
            raise RepositoryError(f"Unexpected error retrieving rules for patient {patient_id}: {e!s}") from e

    async def get_by_provider_id(self, provider_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve all BiometricAlertRules created by a specific provider."""
        try:
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.provider_id == provider_id)
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving rules for provider {provider_id}: {e}")
            raise DatabaseConnectionException(f"Database error retrieving rules for provider {provider_id}: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving rules for provider {provider_id}: {e}")
            raise RepositoryError(f"Unexpected error retrieving rules for provider {provider_id}: {e!s}") from e

    async def get_all_active(self) -> list[BiometricAlertRule]:
        """Retrieve all active BiometricAlertRules."""
        try:
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.is_active)
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving all active rules: {e}")
            raise DatabaseConnectionException(f"Database error retrieving all active rules: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving all active rules: {e}")
            raise RepositoryError(f"Unexpected error retrieving all active rules: {e!s}") from e

    async def get_active_rules_for_patient(self, patient_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve active rules for a specific patient."""
        try:
            stmt = select(BiometricRuleModel).where(
                BiometricRuleModel.patient_id == patient_id,
                BiometricRuleModel.is_active,
            )
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            return [map_rule_model_to_entity(model) for model in rule_models]
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving active rules for patient {patient_id}: {e}")
            raise DatabaseConnectionException(
                f"Database error retrieving active rules for patient {patient_id}: {e!s}"
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving active rules for patient {patient_id}: {e}")
            raise RepositoryError(
                f"Unexpected error retrieving active rules for patient {patient_id}: {e!s}"
            ) from e

    async def save(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Save a BiometricAlertRule entity (create or update)."""
        try:
            if rule.id:
                logger.debug(f"Calling update for rule ID: {rule.id}")
                return await self.update(rule)
            else:
                logger.debug("Calling add for new rule.")
                return await self.add(rule)
        except EntityNotFoundException:
            logger.warning(f"Rule with ID {rule.id} not found for update, attempting to add.")
            rule.id = None
            return await self.add(rule)
        except (DatabaseConnectionException, RepositoryError) as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error saving rule (ID: {rule.id}): {e}")
            raise RepositoryError(f"Unexpected error saving rule: {e!s}") from e

    async def count_active_rules(self, patient_id: UUID) -> int:
        """Count the number of active rules for a patient."""
        try:
            stmt = select(func.count(BiometricRuleModel.id)).where(
                BiometricRuleModel.patient_id == patient_id,
                BiometricRuleModel.is_active
            )
            result = await self.session.execute(stmt)
            count = result.scalar_one_or_none() or 0
            return count
        except SQLAlchemyError as e:
            logger.error(f"Database error counting active rules for patient {patient_id}: {e}")
            raise DatabaseConnectionException(f"Database error counting active rules for patient {patient_id}: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error counting active rules for patient {patient_id}: {e}")
            raise RepositoryError(f"Unexpected error counting active rules for patient {patient_id}: {e!s}") from e

    async def update_active_status(self, rule_id: UUID, is_active: bool) -> bool:
        """Update the active status of a rule. Returns True if updated, False otherwise."""
        try:
            stmt = update(BiometricRuleModel).\
                where(BiometricRuleModel.id == rule_id).\
                values(is_active=is_active).\
                execution_options(synchronize_session="fetch")
            result = await self.session.execute(stmt)
            await self.session.commit()
            updated_count = result.rowcount
            if updated_count == 0:
                logger.warning(f"Rule with ID {rule_id} not found for status update.")
                return False
            logger.info(f"Successfully updated active status for rule {rule_id} to {is_active}")
            return True
        except SQLAlchemyError as e:
            await self.session.rollback()
            logger.error(f"Database error updating active status for rule {rule_id}: {e}")
            raise DatabaseConnectionException(f"Database error updating status for rule {rule_id}: {e!s}") from e
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Unexpected error updating active status for rule {rule_id}: {e}")
            raise RepositoryError(f"Unexpected error updating status for rule {rule_id}: {e!s}") from e


# Factory function for dependency injection
def get_biometric_rule_repository(session: AsyncSession) -> IBiometricRuleRepository:
    """Factory function to create an instance of SQLAlchemyBiometricRuleRepository."""
    logger.debug("Creating SQLAlchemyBiometricRuleRepository instance via factory.")
    return SQLAlchemyBiometricRuleRepository(session=session)

# Export alias to maintain backward compatibility with names used in UnitOfWorkFactory
BiometricRuleRepositoryImpl = SQLAlchemyBiometricRuleRepository
