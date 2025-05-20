"""
Mock Biometric Alert Rule Service.

This module provides a mock implementation of the AlertRuleServiceInterface
for testing and development purposes.
"""

import logging
import uuid
from typing import Any
from uuid import UUID

from app.core.interfaces.services.alert_rule_service_interface import (
    AlertRuleServiceInterface,
)
from app.domain.entities.biometric_alert_rule import (
    AlertPriority,
)

logger = logging.getLogger(__name__)


class MockBiometricAlertRuleService(AlertRuleServiceInterface):
    """Mock implementation of the AlertRuleServiceInterface for testing."""

    def __init__(self):
        """Initialize the mock service."""
        self.rules = {}  # Map of rule_id -> rule
        self.patient_rules = {}  # Map of patient_id -> list of rule_ids

    async def create_rule(self, rule_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new alert rule."""
        rule_id = str(uuid.uuid4())
        patient_id = rule_data.get("patient_id")

        # Create a new rule with the provided data
        rule = {
            "id": rule_id,
            "name": rule_data.get("name", "Unnamed Rule"),
            "description": rule_data.get("description", ""),
            "patient_id": patient_id,
            "conditions": rule_data.get("conditions", []),
            "logical_operator": rule_data.get("logical_operator", "AND"),
            "priority": rule_data.get("priority", AlertPriority.MEDIUM),
            "is_active": rule_data.get("is_active", True),
            "provider_id": rule_data.get("provider_id"),
            "template_id": rule_data.get("template_id"),
        }

        # Store the rule
        self.rules[rule_id] = rule

        # Update patient_rules mapping
        if patient_id:
            if patient_id not in self.patient_rules:
                self.patient_rules[patient_id] = []
            self.patient_rules[patient_id].append(rule_id)

        return rule

    async def update_rule(self, rule_id: UUID | str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update an existing alert rule."""
        rule_id_str = str(rule_id)
        if rule_id_str not in self.rules:
            raise ValueError(f"Rule with ID {rule_id} not found")

        # Update the rule with the provided data
        for key, value in updates.items():
            if key != "id":  # Don't allow changing the ID
                self.rules[rule_id_str][key] = value

        return self.rules[rule_id_str]

    async def delete_rule(self, rule_id: UUID | str) -> bool:
        """Delete an alert rule."""
        rule_id_str = str(rule_id)
        if rule_id_str not in self.rules:
            return False

        # Get the patient ID for this rule
        patient_id = self.rules[rule_id_str].get("patient_id")

        # Remove the rule
        del self.rules[rule_id_str]

        # Update patient_rules mapping
        if patient_id and patient_id in self.patient_rules:
            if rule_id_str in self.patient_rules[patient_id]:
                self.patient_rules[patient_id].remove(rule_id_str)

        return True

    async def get_rule(self, rule_id: UUID | str) -> dict[str, Any] | None:
        """Get a specific rule by ID."""
        return self.rules.get(str(rule_id))

    async def get_rules(
        self,
        patient_id: UUID | str | None = None,
        is_active: bool | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get rules with optional filtering."""
        filtered_rules = []

        # Apply filters
        for rule_id, rule in self.rules.items():
            if patient_id and rule.get("patient_id") != str(patient_id):
                continue
            if is_active is not None and rule.get("is_active") != is_active:
                continue

            filtered_rules.append(rule)

        # Apply pagination
        paginated = filtered_rules[skip : skip + limit]
        return paginated

    async def get_patient_rules(
        self, patient_id: UUID | str, is_active: bool | None = None
    ) -> list[dict[str, Any]]:
        """Get all rules for a specific patient."""
        patient_id_str = str(patient_id)
        if patient_id_str not in self.patient_rules:
            return []

        rules = []
        for rule_id in self.patient_rules[patient_id_str]:
            rule = self.rules.get(rule_id)
            if rule:
                if is_active is None or rule.get("is_active") == is_active:
                    rules.append(rule)

        return rules

    async def toggle_rule_status(self, rule_id: UUID | str, is_active: bool) -> dict[str, Any]:
        """Toggle the active status of a rule."""
        rule_id_str = str(rule_id)
        if rule_id_str not in self.rules:
            raise ValueError(f"Rule with ID {rule_id} not found")

        self.rules[rule_id_str]["is_active"] = is_active
        return self.rules[rule_id_str]

    async def create_rule_from_template(
        self, template_id: UUID, patient_id: UUID, custom_overrides: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a new alert rule based on a template with custom overrides."""
        # In a real implementation, this would fetch the template first
        # For mock purposes, we'll create a basic rule with the template ID

        rule_data = {
            "name": custom_overrides.get("name", "Rule from Template"),
            "description": custom_overrides.get(
                "description", f"Created from template {template_id}"
            ),
            "patient_id": str(patient_id),
            "conditions": custom_overrides.get("conditions", []),
            "logical_operator": custom_overrides.get("logical_operator", "AND"),
            "priority": custom_overrides.get("priority", AlertPriority.MEDIUM),
            "is_active": custom_overrides.get("is_active", True),
            "template_id": str(template_id),
        }

        return await self.create_rule(rule_data)

    async def count_rules_for_patient(
        self, patient_id: UUID | str, is_active: bool | None = None
    ) -> int:
        """Count rules for a patient, optionally filtering by active status."""
        patient_id_str = str(patient_id)
        if patient_id_str not in self.patient_rules:
            return 0

        if is_active is None:
            return len(self.patient_rules[patient_id_str])

        count = 0
        for rule_id in self.patient_rules[patient_id_str]:
            rule = self.rules.get(rule_id)
            if rule and rule.get("is_active") == is_active:
                count += 1

        return count
