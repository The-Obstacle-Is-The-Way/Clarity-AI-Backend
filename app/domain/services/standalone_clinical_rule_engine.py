"""
Standalone Clinical Rule Engine for the Digital Twin Psychiatry Platform.
Used for standalone tests without database dependencies.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any
from uuid import UUID

from app.domain.entities.digital_twin.biometric_rule import (
    BiometricRule,
    LogicalOperator,
    RuleCondition,
    RuleOperator,
)
from app.domain.utils.datetime_utils import UTC


class ClinicalRuleEngine:
    """
    Standalone version of the Clinical Rule Engine for testing.
    """

    def __init__(self) -> None:
        """Initialize without repository dependency for standalone tests."""
        self.rule_templates: dict[str, Any] = {}
        self.custom_conditions: dict[str, Callable] = {}

    def register_rule_template(self, template: dict[str, Any]) -> None:
        """Register a rule template."""
        if "id" not in template:
            raise ValueError("Template must have an ID")
        self.rule_templates[template["id"]] = template

    def register_custom_condition(
        self, condition_id: str, condition_func: Callable
    ) -> None:
        """Register a custom condition function."""
        self.custom_conditions[condition_id] = condition_func

    def create_rule_from_template(
        self,
        template_id: str,
        rule_id: str,
        created_by: UUID,
        parameters: dict[str, Any],
    ) -> BiometricRule:
        """
        Create a rule from a registered template.
        """
        if template_id not in self.rule_templates:
            raise ValueError(f"Unknown template ID: {template_id}")

        template = self.rule_templates[template_id]

        # Check that all required parameters are provided
        required_params = template.get("parameters", [])
        for param in required_params:
            if param not in parameters:
                raise ValueError(f"Missing required parameter: {param}")

        # Process condition threshold parameters
        condition = template["condition"].copy()
        for key, value in condition.items():
            if (
                isinstance(value, str)
                and value.startswith("${")
                and value.endswith("}")
            ):
                param_name = value[2:-1]
                if param_name in parameters:
                    condition[key] = parameters[param_name]

        # Create the rule
        rule = BiometricRule(
            id=rule_id,
            name=template["name"],
            description=template["description"],
            conditions=[
                RuleCondition(
                    data_type=condition["data_type"],
                    operator=RuleOperator(condition["operator"]),
                    threshold_value=condition["threshold"],
                    time_window_hours=condition.get("time_window_hours"),
                )
            ],
            logical_operator=LogicalOperator.AND,
            alert_priority=template["priority"],
            provider_id=created_by,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        return rule
