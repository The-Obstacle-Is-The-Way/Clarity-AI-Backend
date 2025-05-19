"""
BiometricAlertRuleService implementation.

This service manages biometric alert rules, applying domain logic and
orchestrating repository operations for rule creation, retrieval, and management.
"""

import logging
from typing import Any
from uuid import UUID

from app.core.exceptions import ApplicationError, ErrorCode
from app.core.interfaces.services.alert_rule_service_interface import (
    AlertRuleServiceInterface,
)
from app.domain.entities.biometric_alert_rule import (
    AlertPriority,
    BiometricAlertRule,
    BiometricMetricType,
    ComparatorOperator,
    RuleCondition,
    RuleLogicalOperator,
)
from app.domain.repositories.biometric_alert_rule_repository import (
    BiometricAlertRuleRepository,
)
from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)

logger = logging.getLogger(__name__)


class BiometricAlertRuleService(AlertRuleServiceInterface):
    """
    Service for managing biometric alert rules.

    This service implements application logic for creating, updating, retrieving,
    and deleting biometric alert rules, orchestrating domain entities and repositories.
    """

    def __init__(
        self,
        rule_repository: BiometricAlertRuleRepository,
        template_repository: BiometricAlertTemplateRepository,
    ):
        """
        Initialize the service with required repositories.

        Args:
            rule_repository: Repository for alert rules
            template_repository: Repository for alert rule templates
        """
        self.rule_repository = rule_repository
        self.template_repository = template_repository

    async def create_rule_from_template(
        self, template_id: UUID, patient_id: UUID, custom_overrides: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a new alert rule based on a template with custom overrides.

        Args:
            template_id: ID of the template to use
            patient_id: ID of the patient this rule applies to
            custom_overrides: Custom values to override template defaults

        Returns:
            The created alert rule

        Raises:
            ApplicationError: If template not found or creation fails
        """
        logger.info(f"Creating rule from template {template_id} for patient {patient_id}")

        # Get the template from repository
        template = await self.template_repository.get_by_id(template_id)
        if not template:
            logger.error(f"Template {template_id} not found")
            raise ApplicationError(
                code=ErrorCode.NOT_FOUND, message=f"Template {template_id} not found"
            )

        # Create rule based on template
        try:
            # Extract base values from template
            name = custom_overrides.get("name", template.name)
            description = custom_overrides.get("description", template.description)
            priority = custom_overrides.get("priority", template.priority)
            logical_operator = custom_overrides.get("logical_operator", template.logical_operator)

            # Create conditions from template
            conditions = []
            for template_condition in template.conditions:
                # Check if this condition should be overridden
                condition_overrides = custom_overrides.get("conditions", {}).get(
                    str(template_condition.metric_type), {}
                )

                # Create condition with potential overrides
                condition = RuleCondition(
                    metric_type=template_condition.metric_type,
                    operator=condition_overrides.get("operator", template_condition.operator),
                    threshold_value=condition_overrides.get(
                        "threshold_value", template_condition.threshold_value
                    ),
                    description=condition_overrides.get(
                        "description", template_condition.description
                    ),
                )
                conditions.append(condition)

            # Create rule entity
            rule = BiometricAlertRule(
                name=name,
                description=description,
                patient_id=patient_id,
                conditions=conditions,
                logical_operator=logical_operator,
                priority=priority,
                is_active=custom_overrides.get("is_active", True),
                provider_id=custom_overrides.get("provider_id"),
                template_id=template_id,
            )

            # Save to repository
            created_rule = await self.rule_repository.save(rule)
            logger.info(f"Created rule {created_rule.id} from template {template_id}")
            return self._to_dict(created_rule)

        except Exception as e:
            logger.error(f"Failed to create rule from template: {e!s}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to create rule from template: {e!s}",
            )

    async def create_rule(self, rule_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new alert rule from raw data.

        Args:
            rule_data: Data for the new rule

        Returns:
            The created alert rule

        Raises:
            ApplicationError: If validation fails or creation fails
        """
        logger.info(f"Creating rule {rule_data.get('name', 'N/A')}")

        try:
            # Validate patient ID exists
            patient_id = rule_data.get("patient_id")
            if not patient_id:
                raise ApplicationError(
                    code=ErrorCode.VALIDATION_ERROR, message="Patient ID is required"
                )

            # Parse conditions from data
            conditions = []
            raw_conditions = rule_data.get("conditions", [])
            if not raw_conditions:
                raise ApplicationError(
                    code=ErrorCode.VALIDATION_ERROR,
                    message="At least one condition is required",
                )

            for cond_data in raw_conditions:
                try:
                    # Map input metrics to domain entities
                    metric_name = cond_data.get("metric_name", "").lower()
                    metric_type = getattr(BiometricMetricType, metric_name.upper(), None)
                    if not metric_type:
                        raise ValueError(f"Invalid metric name: {metric_name}")

                    # Map input operator to domain entity
                    operator_name = cond_data.get("comparator_operator", "").lower()
                    if operator_name == "greater_than":
                        operator = ComparatorOperator.GREATER_THAN
                    elif operator_name == "less_than":
                        operator = ComparatorOperator.LESS_THAN
                    elif operator_name == "equal_to":
                        operator = ComparatorOperator.EQUAL_TO
                    elif operator_name == "greater_than_or_equal":
                        operator = ComparatorOperator.GREATER_THAN_OR_EQUAL
                    elif operator_name == "less_than_or_equal":
                        operator = ComparatorOperator.LESS_THAN_OR_EQUAL
                    elif operator_name == "not_equal":
                        operator = ComparatorOperator.NOT_EQUAL
                    else:
                        raise ValueError(f"Invalid operator: {operator_name}")

                    # Create condition
                    condition = RuleCondition(
                        metric_type=metric_type,
                        operator=operator,
                        threshold_value=float(cond_data.get("threshold_value", 0)),
                        description=cond_data.get("description"),
                    )
                    conditions.append(condition)
                except (ValueError, TypeError) as e:
                    logger.error(f"Invalid condition data: {e!s}")
                    raise ApplicationError(
                        code=ErrorCode.VALIDATION_ERROR,
                        message=f"Invalid condition data: {e!s}",
                    )

            # Map logical operator
            logical_op_str = rule_data.get("logical_operator", "and").lower()
            logical_operator = (
                RuleLogicalOperator.AND if logical_op_str == "and" else RuleLogicalOperator.OR
            )

            # Map priority
            priority_str = rule_data.get("priority", "medium").lower()
            try:
                priority = getattr(AlertPriority, priority_str.upper())
            except AttributeError:
                priority = AlertPriority.MEDIUM

            # Create rule entity
            rule = BiometricAlertRule(
                name=rule_data.get("name", "Unnamed Rule"),
                description=rule_data.get("description"),
                patient_id=patient_id,
                provider_id=rule_data.get("provider_id"),
                conditions=conditions,
                logical_operator=logical_operator,
                priority=priority,
                is_active=rule_data.get("is_active", True),
            )

            # Save to repository
            created_rule = await self.rule_repository.save(rule)
            logger.info(f"Created rule {created_rule.id}")
            return self._to_dict(created_rule)

        except ApplicationError:
            # Re-raise application errors
            raise
        except Exception as e:
            logger.error(f"Failed to create rule: {e!s}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to create rule: {e!s}",
            )

    async def get_rule_by_id(self, rule_id: UUID) -> dict[str, Any] | None:
        """
        Get a rule by its ID.

        Args:
            rule_id: ID of the rule to retrieve

        Returns:
            The rule if found, None otherwise

        Raises:
            ApplicationError: If retrieval fails
        """
        logger.info(f"Getting rule {rule_id}")

        try:
            rule = await self.rule_repository.get_by_id(rule_id)
            if rule:
                return self._to_dict(rule)
            return None
        except Exception as e:
            logger.error(f"Failed to get rule {rule_id}: {e!s}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR, message=f"Failed to get rule: {e!s}"
            )

    async def get_rules(
        self,
        patient_id: UUID | None = None,
        is_active: bool | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Get rules with optional filtering.

        Args:
            patient_id: Optional filter by patient ID
            is_active: Optional filter by active status
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return

        Returns:
            List of rules matching the criteria

        Raises:
            ApplicationError: If retrieval fails
        """
        logger.info(f"Getting rules (patient={patient_id}, active={is_active})")

        try:
            # Use the repository's get_rules method with filters
            rules = await self.rule_repository.get_rules(patient_id=patient_id, is_active=is_active)
            return [self._to_dict(rule) for rule in rules]
        except Exception as e:
            logger.error(f"Failed to get rules: {e!s}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR, message=f"Failed to get rules: {e!s}"
            )

    async def update_rule(
        self, rule_id: UUID, update_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Update an existing rule.

        Args:
            rule_id: ID of the rule to update
            update_data: Data to update the rule with

        Returns:
            The updated rule or None if not found

        Raises:
            ApplicationError: If validation fails or update fails
        """
        logger.info(f"Updating rule {rule_id}")

        try:
            # Get existing rule
            existing_rule = await self.rule_repository.get_by_id(rule_id)
            if not existing_rule:
                logger.warning(f"Rule {rule_id} not found for update")
                return None

            # Update fields from update_data
            if "name" in update_data:
                existing_rule.name = update_data["name"]

            if "description" in update_data:
                existing_rule.description = update_data["description"]

            if "priority" in update_data:
                priority_str = update_data["priority"].lower()
                try:
                    existing_rule.priority = getattr(AlertPriority, priority_str.upper())
                except AttributeError:
                    # Keep existing if invalid
                    pass

            if "is_active" in update_data:
                existing_rule.is_active = update_data["is_active"]

            if "logical_operator" in update_data:
                op_str = update_data["logical_operator"].lower()
                existing_rule.logical_operator = (
                    RuleLogicalOperator.AND if op_str == "and" else RuleLogicalOperator.OR
                )

            # Update conditions if provided
            if "conditions" in update_data:
                raw_conditions = update_data["conditions"]
                if raw_conditions:  # Only update if non-empty
                    conditions = []
                    for cond_data in raw_conditions:
                        # Map input metrics to domain entities
                        metric_name = cond_data.get("metric_name", "").lower()
                        metric_type = getattr(BiometricMetricType, metric_name.upper(), None)
                        if not metric_type:
                            raise ValueError(f"Invalid metric name: {metric_name}")

                        # Map input operator to domain entity
                        operator_name = cond_data.get("comparator_operator", "").lower()
                        if operator_name == "greater_than":
                            operator = ComparatorOperator.GREATER_THAN
                        elif operator_name == "less_than":
                            operator = ComparatorOperator.LESS_THAN
                        elif operator_name == "equal_to":
                            operator = ComparatorOperator.EQUAL_TO
                        elif operator_name == "greater_than_or_equal":
                            operator = ComparatorOperator.GREATER_THAN_OR_EQUAL
                        elif operator_name == "less_than_or_equal":
                            operator = ComparatorOperator.LESS_THAN_OR_EQUAL
                        elif operator_name == "not_equal":
                            operator = ComparatorOperator.NOT_EQUAL
                        else:
                            raise ValueError(f"Invalid operator: {operator_name}")

                        # Create condition
                        condition = RuleCondition(
                            metric_type=metric_type,
                            operator=operator,
                            threshold_value=float(cond_data.get("threshold_value", 0)),
                            description=cond_data.get("description"),
                        )
                        conditions.append(condition)

                    # Update conditions list
                    existing_rule.conditions = conditions

            # Save updated rule
            updated_rule = await self.rule_repository.save(existing_rule)
            logger.info(f"Updated rule {rule_id}")
            return self._to_dict(updated_rule)

        except ValueError as e:
            logger.error(f"Validation error updating rule: {e!s}")
            raise ApplicationError(
                code=ErrorCode.VALIDATION_ERROR, message=f"Validation error: {e!s}"
            )
        except Exception as e:
            logger.error(f"Failed to update rule {rule_id}: {e!s}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to update rule: {e!s}",
            )

    async def delete_rule(self, rule_id: UUID) -> bool:
        """
        Delete a rule by ID.

        Args:
            rule_id: ID of the rule to delete

        Returns:
            True if deleted, False if not found

        Raises:
            ApplicationError: If deletion fails
        """
        logger.info(f"Deleting rule {rule_id}")

        try:
            return await self.rule_repository.delete(rule_id)
        except Exception as e:
            logger.error(f"Failed to delete rule {rule_id}: {e!s}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to delete rule: {e!s}",
            )

    async def update_rule_active_status(self, rule_id: UUID, is_active: bool) -> bool:
        """
        Update the active status of a rule.

        Args:
            rule_id: ID of the rule to update
            is_active: New active status

        Returns:
            True if updated, False if not found

        Raises:
            ApplicationError: If update fails
        """
        logger.info(f"Updating rule {rule_id} active status to {is_active}")

        try:
            return await self.rule_repository.update_active_status(rule_id, is_active)
        except Exception as e:
            logger.error(f"Failed to update rule {rule_id} active status: {e!s}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to update rule active status: {e!s}",
            )

    async def count_patient_rules(self, patient_id: UUID, is_active: bool | None = None) -> int:
        """
        Count rules for a patient, optionally filtering by active status.

        Args:
            patient_id: ID of the patient
            is_active: Optional filter by active status

        Returns:
            Count of matching rules

        Raises:
            ApplicationError: If count fails
        """
        logger.info(f"Counting rules for patient {patient_id} (active={is_active})")

        try:
            if is_active is not None:
                if is_active:
                    return await self.rule_repository.count_active_rules(patient_id)
                else:
                    # For inactive rules, get all and filter
                    all_rules = await self.rule_repository.get_by_patient_id(patient_id)
                    return len([r for r in all_rules if not r.is_active])
            else:
                # Count all rules for patient
                rules = await self.rule_repository.get_by_patient_id(patient_id)
                return len(rules)
        except Exception as e:
            logger.error(f"Failed to count rules for patient {patient_id}: {e!s}")
            raise ApplicationError(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed to count rules: {e!s}",
            )

    def _to_dict(self, entity: Any) -> dict[str, Any]:
        """
        Convert an entity to a dictionary.

        Args:
            entity: Entity to convert

        Returns:
            Dictionary representation of the entity
        """
        if hasattr(entity, "model_dump"):
            # For pydantic v2 models (preferred)
            return entity.model_dump()
        elif hasattr(entity, "dict"):
            # For older pydantic v1 models (backward compatibility)
            return entity.dict()
        elif hasattr(entity, "__dict__"):
            # For regular classes
            return {k: v for k, v in entity.__dict__.items() if not k.startswith("_")}
        else:
            # For dictionary-like objects
            return dict(entity)
