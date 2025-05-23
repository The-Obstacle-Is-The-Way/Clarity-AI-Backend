"""
SQLAlchemy implementation of the BiometricAlertRuleRepository.
"""
from uuid import UUID, uuid4  # Standard library

from sqlalchemy.ext.asyncio import AsyncSession  # Third-party

from app.domain.entities.biometric_alert_rule import BiometricAlertRule  # First-party
from app.domain.entities.biometric_rule import BiometricRule
from app.domain.repositories.biometric_alert_rule_repository import (
    BiometricAlertRuleRepository,
)
from app.infrastructure.persistence.sqlalchemy.repositories.biometric_rule_repository import (
    SQLAlchemyBiometricRuleRepository,
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
        rule = await self._delegate.get_by_id(rule_id)
        return _convert_biometric_rule_to_alert_rule(rule) if rule else None

    async def get_all(self) -> list[BiometricAlertRule]:
        """Retrieve all rules using the delegate repository."""
        rules = await self._delegate.list_all()
        return [_convert_biometric_rule_to_alert_rule(rule) for rule in rules]

    async def get_by_patient_id(self, patient_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve rules for a patient using the delegate repository."""
        rules = await self._delegate.get_by_patient_id(patient_id)
        return [_convert_biometric_rule_to_alert_rule(rule) for rule in rules]

    async def get_by_provider_id(self, provider_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve all rules created by a specific provider."""
        rules = await self._delegate.get_by_provider_id(provider_id)
        return [_convert_biometric_rule_to_alert_rule(rule) for rule in rules]

    async def get_all_active(self) -> list[BiometricAlertRule]:
        """Retrieve all active rules using the delegate repository."""
        rules = await self._delegate.get_active_rules()
        return [_convert_biometric_rule_to_alert_rule(rule) for rule in rules]

    async def get_active_rules_for_patient(self, patient_id: UUID) -> list[BiometricAlertRule]:
        """Retrieve active rules for a patient by filtering delegate results."""
        rules = await self._delegate.get_active_rules(patient_id)
        return [_convert_biometric_rule_to_alert_rule(rule) for rule in rules]

    async def save(self, rule: BiometricAlertRule) -> BiometricAlertRule:
        """Create or update a rule using the delegate repository."""
        # Convert BiometricAlertRule to BiometricRule for delegation
        biometric_rule = _convert_alert_rule_to_biometric_rule(rule)
        saved_rule = await self._delegate.save(biometric_rule)
        return _convert_biometric_rule_to_alert_rule(saved_rule)

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
        self, patient_id: UUID | None = None, is_active: bool | None = None
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


def _convert_biometric_rule_to_alert_rule(rule: BiometricRule) -> BiometricAlertRule:
    """Convert BiometricRule to BiometricAlertRule."""
    from app.domain.entities.biometric_alert_rule import (
        RuleCondition as AlertRuleCondition,
        ComparatorOperator,
        RuleLogicalOperator,
        AlertPriority as AlertRulePriority,
        BiometricMetricType,
    )
    
    # Convert conditions
    alert_conditions = []
    for condition in rule.conditions:
        # Map operator types
        operator_mapping = {
            "GREATER_THAN": ComparatorOperator.GREATER_THAN,
            "LESS_THAN": ComparatorOperator.LESS_THAN,
            "EQUAL_TO": ComparatorOperator.EQUAL_TO,
            "GREATER_THAN_OR_EQUAL": ComparatorOperator.GREATER_THAN_OR_EQUAL,
            "LESS_THAN_OR_EQUAL": ComparatorOperator.LESS_THAN_OR_EQUAL,
            "NOT_EQUAL": ComparatorOperator.NOT_EQUAL,
        }
        
        operator_name = condition.operator.name if hasattr(condition.operator, 'name') else str(condition.operator)
        mapped_operator = operator_mapping.get(operator_name, ComparatorOperator.GREATER_THAN)
        
        # Convert metric name to BiometricMetricType
        metric_type = BiometricMetricType.HEART_RATE  # default
        if hasattr(condition, 'metric_name') and condition.metric_name:
            try:
                metric_type = BiometricMetricType(condition.metric_name.lower())
            except ValueError:
                pass  # use default
        
        alert_condition = AlertRuleCondition(
            metric_type=metric_type,
            operator=mapped_operator,
            threshold_value=float(condition.threshold_value),
        )
        alert_conditions.append(alert_condition)
    
    # Map logical operator
    logical_op = RuleLogicalOperator.AND  # default
    if hasattr(rule, 'logical_operator'):
        if str(rule.logical_operator).lower() == 'or':
            logical_op = RuleLogicalOperator.OR
    
    # Map priority
    priority_mapping = {
        "LOW": AlertRulePriority.LOW,
        "MEDIUM": AlertRulePriority.MEDIUM,
        "HIGH": AlertRulePriority.HIGH,
        "CRITICAL": AlertRulePriority.CRITICAL,
        "INFO": AlertRulePriority.INFO,
    }
    
    priority_name = rule.priority.name if hasattr(rule.priority, 'name') else str(rule.priority)
    mapped_priority = priority_mapping.get(priority_name, AlertRulePriority.MEDIUM)
    
    # Handle missing patient_id - BiometricAlertRule requires it
    if rule.patient_id is None:
        patient_id = uuid4()  # Create a placeholder UUID
    else:
        patient_id = rule.patient_id
    
    return BiometricAlertRule(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        patient_id=patient_id,
        provider_id=rule.provider_id,
        conditions=alert_conditions,
        logical_operator=logical_op,
        priority=mapped_priority,
        is_active=rule.is_active,
        created_at=rule.created_at,
        updated_at=getattr(rule, 'updated_at', None),
    )


def _convert_alert_rule_to_biometric_rule(rule: BiometricAlertRule) -> BiometricRule:
    """Convert BiometricAlertRule to BiometricRule."""
    from app.domain.entities.biometric_rule import (
        RuleCondition,
        RuleOperator,
        LogicalOperator,
        AlertPriority,
    )
    
    # Convert conditions
    biometric_conditions = []
    for condition in rule.conditions:
        # Map operator types
        operator_mapping = {
            ">": RuleOperator.GREATER_THAN,
            "<": RuleOperator.LESS_THAN,
            "==": RuleOperator.EQUAL_TO,
            ">=": RuleOperator.GREATER_THAN_OR_EQUAL,
            "<=": RuleOperator.LESS_THAN_OR_EQUAL,
            "!=": RuleOperator.NOT_EQUAL,
        }
        
        mapped_operator = operator_mapping.get(condition.operator.value, RuleOperator.GREATER_THAN)
        
        biometric_condition = RuleCondition(
            metric_name=condition.metric_type.value,
            operator=mapped_operator,
            threshold_value=condition.threshold_value,
            data_type="float",  # default data type
        )
        biometric_conditions.append(biometric_condition)
    
    # Map logical operator
    logical_op = LogicalOperator.AND  # default
    if rule.logical_operator == "or":
        logical_op = LogicalOperator.OR
    
    # Map priority
    priority_mapping = {
        "low": AlertPriority.LOW,
        "medium": AlertPriority.MEDIUM,
        "high": AlertPriority.HIGH,
        "critical": AlertPriority.CRITICAL,
        "info": AlertPriority.INFO,
    }
    
    mapped_priority = priority_mapping.get(rule.priority.value, AlertPriority.MEDIUM)
    
    return BiometricRule(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        patient_id=rule.patient_id,
        provider_id=rule.provider_id,
        conditions=biometric_conditions,
        logical_operator=logical_op,
        priority=mapped_priority,
        is_active=rule.is_active,
        # BiometricRule doesn't have created_at/updated_at as required fields
    )
