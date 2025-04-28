"""
SQLAlchemy implementation of the BiometricAlertRuleRepository.
"""
from typing import List, Optional
from uuid import UUID

from app.domain.entities.biometric_alert_rule import BiometricAlertRule
from app.domain.repositories.biometric_alert_rule_repository import BiometricAlertRuleRepository


class SQLAlchemyBiometricAlertRuleRepository(BiometricAlertRuleRepository):
    """SQLAlchemy implementation of BiometricAlertRuleRepository."""
    
    async def get_by_id(self, rule_id: UUID) -> Optional[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return None
    
    async def get_all(self) -> List[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def get_by_patient_id(self, patient_id: UUID) -> List[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def get_by_provider_id(self, provider_id: UUID) -> List[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def get_all_active(self) -> List[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def get_active_rules_for_patient(self, patient_id: UUID) -> List[BiometricAlertRule]:
        """Mock implementation for test collection."""
        return []
    
    async def save(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Mock implementation for test collection."""
        return rule
    
    async def delete(self, rule_id: UUID) -> bool:
        """Mock implementation for test collection."""
        return True
    
    async def count_active_rules(self, patient_id: UUID) -> int:
        """Mock implementation for test collection."""
        return 0
    
    async def update_active_status(self, rule_id: UUID, is_active: bool) -> bool:
        """Mock implementation for test collection."""
        return True
