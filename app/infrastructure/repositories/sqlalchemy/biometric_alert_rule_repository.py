"""
SQLAlchemy implementation of the BiometricAlertRuleRepository.
"""
from uuid import UUID  # Standard library

from sqlalchemy.ext.asyncio import AsyncSession  # Third-party
from sqlalchemy import select, func, update

from app.domain.entities.biometric_alert_rule import BiometricAlertRule  # First-party
from app.domain.repositories.biometric_alert_rule_repository import BiometricAlertRuleRepository
from app.infrastructure.persistence.sqlalchemy.repositories.biometric_rule_repository import (
    SQLAlchemyBiometricRuleRepository,
)
from app.infrastructure.persistence.sqlalchemy.models.biometric_rule import BiometricRuleModel
from app.infrastructure.persistence.sqlalchemy.mappers.biometric_rule_mapper import (
    map_rule_model_to_entity,
)

# Import necessary exceptions if needed for real implementation
# from app.domain.exceptions import RepositoryError, ValidationError


class SQLAlchemyBiometricAlertRuleRepository(BiometricAlertRuleRepository):
    """SQLAlchemy implementation of BiometricAlertRuleRepository."""

    def __init__(self, db: AsyncSession):
        """Initialize repository with DB session and set up delegate repository."""
        self.db = db
        # Re-use the fully-featured implementation to avoid code duplication
        self._delegate = SQLAlchemyBiometricRuleRepository(session=db)

    async def get_by_id(self, rule_id: UUID) -> BiometricAlertRule | None:
        """Retrieve a rule by ID using the delegate repository."""
        return await self._delegate.get_by_id(rule_id)

    async def get_all(self) -> list[BiometricAlertRule]:
        """Retrieve all rules using the delegate repository."""
        return await self._delegate.get_all()

    async def get_by_patient_id(self, patient_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve rules for a patient using the delegate repository."""
        return await self._delegate.get_by_patient_id(patient_id)

    async def get_by_provider_id(self, provider_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve all rules created by a specific provider."""
        stmt = select(BiometricRuleModel).where(BiometricRuleModel.provider_id == provider_id)
        result = await self.db.execute(stmt)
        models = result.scalars().all()
        return [map_rule_model_to_entity(m) for m in models]

    async def get_all_active(self) -> list[BiometricAlertRule]:
        """Retrieve all active rules using the delegate repository."""
        return await self._delegate.get_all_active()

    async def get_active_rules_for_patient(self, patient_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve active rules for a patient by filtering delegate results."""
        rules = await self._delegate.get_by_patient_id(patient_id)
        return [rule for rule in rules if rule.is_active]

    async def save(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Create or update a rule using the delegate repository."""
        return await self._delegate.save(rule)

    async def delete(self, rule_id: UUID) -> bool:
        """Delete a rule using the delegate repository."""
        return await self._delegate.delete(rule_id)

    async def count_active_rules(self, patient_id: UUID) -> int:
        """Count active rules for a patient using the delegate repository."""
        return await self._delegate.count_active_rules(patient_id)

    async def update_active_status(self, rule_id: UUID, is_active: bool) -> bool:
        """Update active status using the delegate repository."""
        return await self._delegate.update_active_status(rule_id, is_active)

    # Aliases for backward compatibility / specific use cases
    async def get_rules(
        self,
        patient_id: UUID | None = None,
        is_active: bool | None = None
    ) -> list[BiometricAlertRule]:
        """Retrieve rules, optionally filtering by patient_id and is_active status."""
        # This logic implements the filtering based on provided parameters
        print(
            f"\nWARNING: Using placeholder "
            f"SQLAlchemyBiometricAlertRuleRepository.get_rules("
            f"patient_id={patient_id}, is_active={is_active})\n"
        )
        if patient_id is not None and is_active is not None:
            if is_active:
                # Get active rules for a specific patient
                # In real implementation: Query DB for rules where patient_id=X and is_active=True
                return await self.get_active_rules_for_patient(patient_id)
            else:
                # Get inactive rules for a specific patient
                # In real implementation: Query DB for rules where patient_id=X and is_active=False
                all_patient_rules = await self.get_by_patient_id(patient_id)
                return [rule for rule in all_patient_rules if not rule.is_active]
        elif patient_id is not None:
            # Get all rules for a specific patient
            return await self.get_by_patient_id(patient_id)
        elif is_active is not None:
            if is_active:
                # Get all active rules
                return await self.get_all_active()
            else:
                # Get all inactive rules
                # In real implementation: Query DB for rules where is_active=False
                all_rules = await self.get_all()
                return [rule for rule in all_rules if not rule.is_active]
        else:
            # Get all rules (no filters)
            return await self.get_all()

    async def get_rule_by_id(self, rule_id: UUID) -> BiometricAlertRule | None:
        """Alias for get_by_id()"""
        return await self.get_by_id(rule_id)

    async def create_rule(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Alias for save() for new rules"""
        return await self.save(rule)

    async def update_rule(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Alias for save() for existing rules"""
        # In a real implementation, might check if rule exists first
        return await self.save(rule)

    async def delete_rule(self, rule_id: UUID) -> bool:
        """Alias for delete()"""
        return await self.delete(rule_id)
