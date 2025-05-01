"""
SQLAlchemy implementation of the BiometricAlertRuleRepository.
"""
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.biometric_alert_rule import BiometricAlertRule
from app.domain.repositories.biometric_alert_rule_repository import BiometricAlertRuleRepository

class SQLAlchemyBiometricAlertRuleRepository(BiometricAlertRuleRepository):
    """SQLAlchemy implementation of BiometricAlertRuleRepository."""
    
    def __init__(self, db: AsyncSession):
        """Initialize repository with DB session."""
        self.db = db
    
    async def get_by_id(self, rule_id: uuid.UUID) -> BiometricAlertRule | None:
        """Mock implementation for test collection."""
        return None
    
    async def get_all(self) -> list[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def get_by_patient_id(self, patient_id: uuid.UUID) -> list[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def get_by_provider_id(self, provider_id: uuid.UUID) -> list[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def get_all_active(self) -> list[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def get_active_rules_for_patient(self, patient_id: uuid.UUID) -> list[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def save(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Mock implementation for test collection."""
        return rule
    
    async def delete(self, rule_id: uuid.UUID) -> bool:
        """Mock implementation for test collection."""
        return True
    
    async def count_active_rules(self, patient_id: uuid.UUID) -> int:
        """Mock implementation for test collection."""
        return 0
    
    async def update_active_status(self, rule_id: uuid.UUID, is_active: bool) -> bool:
        """Mock implementation for test collection."""
        return True

    async def get_rules(
        self,
        patient_id: uuid.UUID | None = None,
        is_active: bool | None = None
    ) -> list[BiometricAlertRule]:
        """Retrieve rules, optionally filtering by patient_id and is_active status."""
        print(
            f"\nWARNING: Using placeholder "
            f"SQLAlchemyBiometricAlertRuleRepository.get_rules("
            f"patient_id={patient_id}, is_active={is_active})\n"
        )
        if patient_id is not None and is_active is not None:
            if is_active:
                return await self.get_active_rules_for_patient(patient_id)
            else:
                all_patient_rules = await self.get_by_patient_id(patient_id)
                return [rule for rule in all_patient_rules if not rule.is_active]
        elif patient_id is not None:
            return await self.get_by_patient_id(patient_id)
        elif is_active is not None:
            if is_active:
                return await self.get_all_active()
            else:
                all_rules = await self.get_all()
                return [rule for rule in all_rules if not rule.is_active]
        else:
            return await self.get_all()

    async def get_rule_by_id(self, rule_id: uuid.UUID) -> BiometricAlertRule | None:
        """Alias for get_by_id()"""
        return await self.get_by_id(rule_id)

    async def create_rule(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Alias for save() for new rules"""
        return await self.save(rule)

    async def update_rule(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Alias for save() for existing rules"""
        return await self.save(rule)

    async def delete_rule(self, rule_id: uuid.UUID) -> bool:
        """Alias for delete()"""
        return await self.delete(rule_id)
