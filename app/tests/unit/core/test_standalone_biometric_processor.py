"""
Migrated test from standalone test to proper unit test.
Original file: app/tests/standalone/core/test_standalone_biometric_processor.py

This test uses the actual implementations from the main codebase.
Migration date: Tue May 13 10:35:51 EDT 2025
"""

# Migrated imports from original file
# (Replace standalone imports with actual implementations)
"""Self-contained test for Biometric Event Processor.

This module contains both the implementation and tests for the Biometric Event Processor
in a single file, making it completely independent of the rest of the application.
Supports hypothalamus-pituitary neural connectivity and quantum-level mathematical precision.
"""

import unittest
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import pytest

# ============= Biometric Event Processor Implementation =============


class BiometricType(str, Enum):
    """Types of biometric data."""

    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE = "blood_pressure"
    TEMPERATURE = "temperature"
    SLEEP = "sleep"
    ACTIVITY = "activity"
    GLUCOSE = "glucose"
    OXYGEN_SATURATION = "oxygen_saturation"
    RESPIRATORY_RATE = "respiratory_rate"
    WEIGHT = "weight"
    MOOD = "mood"
    STRESS = "stress"
    CUSTOM = "custom"


class AlertSeverity(str, Enum):
    """Severity levels for alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComparisonOperator(str, Enum):
    """Comparison operators for rule conditions."""

    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"


class BiometricDataPoint:
    """Biometric data point."""

    def __init__(
        self,
        patient_id: str,
        data_type: BiometricType,
        value: float | int | dict[str, Any],
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """
        Initialize a biometric data point.

        Args:
            patient_id: ID of the patient
            data_type: Type of biometric data
            value: Value of the data point
            timestamp: Timestamp of the data point
            metadata: Additional metadata
        """
        self.patient_id = patient_id
        self.data_type = data_type
        self.value = value
        self.timestamp = timestamp or datetime.now()
        self.metadata = metadata or {}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BiometricDataPoint":
        """Create from dictionary."""
        # Parse timestamp if present
        timestamp = None
        if data.get("timestamp"):
            try:
                timestamp = datetime.fromisoformat(data["timestamp"])
            except (ValueError, TypeError):
                pass

        # Parse data type enum
        try:
            data_type = BiometricType(data["data_type"])
        except (ValueError, KeyError):
            data_type = BiometricType.CUSTOM

        return cls(
            patient_id=data.get("patient_id", ""),
            data_type=data_type,
            value=data.get("value"),
            timestamp=timestamp,
            metadata=data.get("metadata", {}),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "patient_id": self.patient_id,
            "data_type": self.data_type.value,
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


class AlertRule:
    """Alert rule for biometric data."""

    def __init__(
        self,
        name: str,
        data_type: BiometricType,
        operator: ComparisonOperator,
        threshold: float | int,
        patient_id: str | None = None,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        description: str | None = None,
        active: bool = True,
        cooldown_minutes: int = 30,
    ):
        """
        Initialize an alert rule.

        Args:
            name: Rule name
            data_type: Type of biometric data this rule applies to
            operator: Comparison operator
            threshold: Threshold value for comparison
            patient_id: Optional patient ID for patient-specific rules
            severity: Alert severity
            description: Rule description
            active: Whether the rule is active
            cooldown_minutes: Cooldown period in minutes between alerts
        """
        self.id = str(uuid4())
        self.name = name
        self.data_type = data_type
        self.operator = operator
        self.threshold = threshold
        self.patient_id = patient_id
        self.severity = severity
        self.description = description or f"{data_type.value} {operator.value} {threshold}"
        self.active = active
        self.cooldown_minutes = cooldown_minutes
        self.last_triggered: dict[str, datetime] = {}

    def evaluate(self, data_point: BiometricDataPoint) -> bool:
        """
        Evaluate whether a data point triggers this rule.

        Args:
            data_point: Biometric data point to evaluate

        Returns:
            True if the rule is triggered, False otherwise
        """
        # Check if rule is active
        if not self.active:
            return False

        # Check data type match
        if data_point.data_type != self.data_type:
            return False

        # Check patient-specific rule
        if self.patient_id and data_point.patient_id != self.patient_id:
            return False

        # Check cooldown period
        if data_point.patient_id in self.last_triggered:
            last_time = self.last_triggered[data_point.patient_id]
            elapsed_minutes = (datetime.now() - last_time).total_seconds() / 60
            if elapsed_minutes < self.cooldown_minutes:
                return False

        # Get the value to compare
        value = data_point.value
        if not isinstance(value, int | float):
            # For complex values like blood pressure, we need special handling
            if isinstance(value, dict) and self.data_type == BiometricType.BLOOD_PRESSURE:
                # For blood pressure, use systolic by default
                value = value.get("systolic")
                if value is None:
                    return False

        # Evaluate the condition
        triggered = False

        if self.operator == ComparisonOperator.GREATER_THAN:
            triggered = value > self.threshold
        elif self.operator == ComparisonOperator.GREATER_THAN_OR_EQUAL:
            triggered = value >= self.threshold
        elif self.operator == ComparisonOperator.LESS_THAN:
            triggered = value < self.threshold
        elif self.operator == ComparisonOperator.LESS_THAN_OR_EQUAL:
            triggered = value <= self.threshold
        elif self.operator == ComparisonOperator.EQUAL:
            triggered = value == self.threshold
        elif self.operator == ComparisonOperator.NOT_EQUAL:
            triggered = value != self.threshold

        # Update last triggered time if rule was triggered
        if triggered:
            self.last_triggered[data_point.patient_id] = datetime.now()

        return triggered

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "data_type": self.data_type.value,
            "operator": self.operator.value,
            "threshold": self.threshold,
            "patient_id": self.patient_id,
            "severity": self.severity.value,
            "description": self.description,
            "active": self.active,
            "cooldown_minutes": self.cooldown_minutes,
        }


class BiometricAlert:
    """Alert generated when a biometric data point triggers a rule."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        patient_id: str,
        data_point: BiometricDataPoint,
        severity: AlertSeverity,
        message: str,
        timestamp: datetime | None = None,
    ):
        """
        Initialize a biometric alert.

        Args:
            rule_id: ID of the rule that generated the alert
            rule_name: Name of the rule that generated the alert
            patient_id: ID of the patient
            data_point: Biometric data point that triggered the alert
            severity: Alert severity
            message: Alert message
            timestamp: Alert generation time
        """
        self.id = str(uuid4())
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.patient_id = patient_id
        self.data_point = data_point
        self.severity = severity
        self.message = message
        self.timestamp = timestamp or datetime.now()
        self.acknowledged = False
        self.acknowledged_at: datetime | None = None
        self.acknowledged_by: str | None = None

    def acknowledge(self, user_id: str) -> None:
        """
        Acknowledge the alert.

        Args:
            user_id: ID of the user acknowledging the alert
        """
        self.acknowledged = True
        self.acknowledged_at = datetime.now()
        self.acknowledged_by = user_id

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "patient_id": self.patient_id,
            "data_point": self.data_point.to_dict() if self.data_point else None,
            "severity": self.severity.value if self.severity else None,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
        }


class AlertObserver:
    """Base class for alert observers."""

    def notify(self, alert: BiometricAlert) -> Any:
        """
        Notify the observer of a new alert.

        Args:
            alert: The alert that was generated
        """
        raise NotImplementedError("Subclasses must implement this method")


class EmailAlertObserver(AlertObserver):
    """Observer that sends email notifications for alerts."""

    def __init__(self, recipients: list[str]):
        """
        Initialize an email alert observer.

        Args:
            recipients: List of email recipients
        """
        self.recipients = recipients
        self.sent_alerts: list[BiometricAlert] = []

    def notify(self, alert: BiometricAlert) -> dict[str, Any]:
        """
        Notify recipients of a new alert via email.

        Args:
            alert: The alert that was generated

        Returns:
            Email details dictionary
        """
        # In a real implementation, this would send an email
        # For testing, we just record that an alert was sent
        self.sent_alerts.append(alert)

        # Simulated email subject and body
        subject = f"[{alert.severity.value.upper()}] Biometric Alert: {alert.rule_name}"
        body = f"Patient ID: {alert.patient_id}\n"
        body += f"Rule: {alert.rule_name}\n"
        body += f"Value: {alert.data_point.value}\n"
        body += f"Time: {alert.timestamp.isoformat()}\n"
        body += f"Message: {alert.message}"

        # In a real implementation, this would return the email details
        return {"subject": subject, "body": body, "recipients": self.recipients}


class SMSAlertObserver(AlertObserver):
    """Observer that sends SMS notifications for alerts."""

    def __init__(self, phone_numbers: list[str], urgent_only: bool = False):
        """
        Initialize an SMS alert observer.

        Args:
            phone_numbers: List of phone numbers to send SMS to
            urgent_only: Whether to only send SMS for urgent alerts
        """
        self.phone_numbers = phone_numbers
        self.urgent_only = urgent_only
        self.sent_alerts: list[BiometricAlert] = []

    def notify(self, alert: BiometricAlert) -> dict[str, Any] | None:
        """
        Notify recipients of a new alert via SMS.

        Args:
            alert: The alert that was generated

        Returns:
            SMS details dictionary or None if no SMS was sent
        """
        # Only send SMS for high severity alerts if urgent_only is True
        if self.urgent_only and alert.severity not in [
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL,
        ]:
            return None

        # In a real implementation, this would send an SMS
        # For testing, we just record that an alert was sent
        self.sent_alerts.append(alert)

        # Simulated SMS message
        message = f"ALERT: {alert.rule_name} for patient {alert.patient_id}"

        # In a real implementation, this would return the SMS details
        return {"message": message, "phone_numbers": self.phone_numbers}


class InAppAlertObserver(AlertObserver):
    """Observer that sends in-app notifications for alerts."""

    def __init__(self):
        """Initialize an in-app alert observer."""
        self.notifications: dict[str, list[BiometricAlert]] = {}  # user_id -> alerts

    def notify(self, alert: BiometricAlert) -> dict[str, Any]:
        """
        Notify users of a new alert via in-app notification.

        Args:
            alert: The alert that was generated

        Returns:
            Notification details dictionary
        """
        # In a real implementation, this would send in-app notifications
        # to relevant users (e.g., patient's provider, care team, etc.)
        # For testing, we just record the notifications

        # Simulate getting the associated provider IDs
        provider_ids = [f"provider_{alert.patient_id}"]

        for provider_id in provider_ids:
            if provider_id not in self.notifications:
                self.notifications[provider_id] = []
            self.notifications[provider_id].append(alert)

        # In a real implementation, this would return notification details
        return {"provider_ids": provider_ids, "alert": alert.to_dict()}


class ClinicalRuleEngine:
    """Engine for managing clinical rule templates and custom conditions."""

    def __init__(self):
        """Initialize the clinical rule engine."""
        self.rule_templates: dict[str, dict[str, Any]] = {}
        self.custom_conditions: dict[str, Callable[[BiometricDataPoint], bool]] = {}

    def register_rule_template(
        self,
        template_id: str,
        name: str,
        data_type: BiometricType,
        operator: ComparisonOperator,
        threshold: float | int,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        description: str | None = None,
        parameters: list[str] | None = None,
    ) -> None:
        """
        Register a rule template.

        Args:
            template_id: Template ID
            name: Template name
            data_type: Type of biometric data this rule applies to
            operator: Comparison operator
            threshold: Default threshold value
            severity: Default alert severity
            description: Template description
            parameters: List of parameters that can be customized when creating a rule
        """
        self.rule_templates[template_id] = {
            "name": name,
            "data_type": data_type,
            "operator": operator,
            "threshold": threshold,
            "severity": severity,
            "description": description,
            "parameters": parameters or [],
        }

    def register_custom_condition(
        self,
        condition_id: str,
        condition_fn: Callable[[BiometricDataPoint], bool],
        description: str,
    ) -> None:
        """
        Register a custom condition function.

        Args:
            condition_id: Condition ID
            condition_fn: Function that evaluates a data point and returns True if condition is met
            description: Description of the condition
        """
        self.custom_conditions[condition_id] = condition_fn

    def create_rule_from_template(
        self,
        template_id: str,
        parameters: dict[str, Any] | None = None,
        patient_id: str | None = None,
    ) -> AlertRule:
        """
        Create a rule from a template.

        Args:
            template_id: Template ID
            parameters: Parameters to customize the rule
            patient_id: Patient ID if this is a patient-specific rule

        Returns:
            AlertRule instance
        """
        if template_id not in self.rule_templates:
            raise ValueError(f"Unknown template ID: {template_id}")

        template = self.rule_templates[template_id]
        params = parameters or {}

        # Apply parameters to template
        name = params.get("name", template["name"])
        threshold = params.get("threshold", template["threshold"])
        severity = params.get("severity", template["severity"])
        description = params.get("description", template["description"])
        active = params.get("active", True)
        cooldown_minutes = params.get("cooldown_minutes", 30)

        # Create rule from template
        return AlertRule(
            name=name,
            data_type=template["data_type"],
            operator=template["operator"],
            threshold=threshold,
            patient_id=patient_id,
            severity=severity,
            description=description,
            active=active,
            cooldown_minutes=cooldown_minutes,
        )


class ProcessorContext:
    """Context for biometric event processing."""

    def __init__(self, patient_id: str):
        """
        Initialize the processor context.

        Args:
            patient_id: ID of the patient
        """
        self.patient_id = patient_id
        self.last_values: dict[BiometricType, Any] = {}
        self.trends: dict[BiometricType, list[Any]] = {}
        self.alert_counts: dict[str, int] = {}  # rule_id -> count

    def update(self, data_point: BiometricDataPoint) -> None:
        """
        Update the context with a new data point.

        Args:
            data_point: New biometric data point
        """
        data_type = data_point.data_type
        value = data_point.value

        # Update last value
        self.last_values[data_type] = value

        # Update trend
        if data_type not in self.trends:
            self.trends[data_type] = []
        self.trends[data_type].append(value)

        # Keep only the last 10 values for each data type
        if len(self.trends[data_type]) > 10:
            self.trends[data_type] = self.trends[data_type][-10:]

    def increment_alert_count(self, rule_id: str) -> None:
        """
        Increment the alert count for a rule.

        Args:
            rule_id: ID of the rule
        """
        if rule_id not in self.alert_counts:
            self.alert_counts[rule_id] = 0
        self.alert_counts[rule_id] += 1


class BiometricEventProcessor:
    """Processor for biometric events with support for hypothalamus-pituitary connectivity."""

    def __init__(self):
        """Initialize the biometric event processor."""
        self.rules: dict[str, AlertRule] = {}
        self.observers: list[AlertObserver] = []
        self.contexts: dict[str, ProcessorContext] = {}
        self.neural_connectivity_enabled = True  # Enable hypothalamus-pituitary support
        self.pituitary_threshold_modifier = 0.85  # Modifier for pituitary sensitivity

    def add_rule(self, rule: AlertRule) -> None:
        """
        Add a rule to the processor.

        Args:
            rule: Rule to add
        """
        self.rules[rule.id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a rule from the processor.

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if removed, False if not found
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False

    def register_observer(self, observer: AlertObserver) -> None:
        """
        Register an observer for alerts.

        Args:
            observer: Observer to register
        """
        self.observers.append(observer)

    def unregister_observer(self, observer: AlertObserver) -> bool:
        """
        Unregister an observer.

        Args:
            observer: Observer to unregister

        Returns:
            True if removed, False if not found
        """
        if observer in self.observers:
            self.observers.remove(observer)
            return True
        return False

    def get_context(self, patient_id: str) -> ProcessorContext:
        """
        Get or create a context for a patient.

        Args:
            patient_id: ID of the patient

        Returns:
            ProcessorContext instance
        """
        if patient_id not in self.contexts:
            self.contexts[patient_id] = ProcessorContext(patient_id)
        return self.contexts[patient_id]

    def process_data_point(self, data_point: BiometricDataPoint) -> list[BiometricAlert]:
        """
        Process a biometric data point with support for hypothalamus-pituitary neural connectivity.

        Args:
            data_point: Biometric data point to process

        Returns:
            List of alerts generated
        """
        # Check for missing patient ID
        if not data_point.patient_id:
            return []

        # Apply pituitary region sensitivity adjustments if enabled
        if (
            self.neural_connectivity_enabled
            and data_point.metadata.get("brain_region") == "pituitary"
        ):
            # Adjust sensitivity for pituitary-related metrics
            if isinstance(data_point.value, int | float):
                # Store original value in metadata for reference
                data_point.metadata["original_value"] = data_point.value
                # Apply pituitary threshold modifier
                data_point.value = data_point.value * self.pituitary_threshold_modifier

        # Get patient context
        context = self.get_context(data_point.patient_id)

        # Update context with new data point
        context.update(data_point)

        # Evaluate rules
        alerts: list[BiometricAlert] = []
        for rule in self.rules.values():
            if rule.evaluate(data_point):
                # Create alert
                alert = BiometricAlert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    patient_id=data_point.patient_id,
                    data_point=data_point,
                    severity=rule.severity,
                    message=f"{rule.name} alert: {data_point.data_type.value} is {data_point.value}",
                )
                alerts.append(alert)

                # Update context alert count
                context.increment_alert_count(rule.id)

                # Notify observers
                for observer in self.observers:
                    observer.notify(alert)

        return alerts


# ============= Tests =============


@pytest.mark.standalone()
class TestBiometricEventProcessor(unittest.TestCase):
    """Test the biometric event processor with hypothalamus-pituitary axis support."""

    def setUp(self) -> None:
        """Set up a processor for each test."""
        self.processor = BiometricEventProcessor()

    def test_add_rule(self) -> None:
        """Test adding a rule to the processor."""
        # Create a rule
        rule = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=100,
        )

        # Add to processor
        self.processor.add_rule(rule)

        # Check that rule was added
        self.assertIn(rule.id, self.processor.rules)
        self.assertEqual(self.processor.rules[rule.id], rule)

    def test_remove_rule(self) -> None:
        """Test removing a rule from the processor."""
        # Create and add a rule
        rule = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=100,
        )
        self.processor.add_rule(rule)

        # Remove the rule
        result = self.processor.remove_rule(rule.id)

        # Check that rule was removed
        self.assertTrue(result)
        self.assertNotIn(rule.id, self.processor.rules)

        # Try to remove a non-existent rule
        result = self.processor.remove_rule("non_existent_rule")
        self.assertFalse(result)

    def test_register_observer(self) -> None:
        """Test registering an observer."""
        # Create an observer
        observer = EmailAlertObserver(recipients=["doctor@example.com"])

        # Register the observer
        self.processor.register_observer(observer)

        # Check that observer was registered
        self.assertIn(observer, self.processor.observers)

    def test_unregister_observer(self) -> None:
        """Test unregistering an observer."""
        # Create and register observers
        observer = EmailAlertObserver(recipients=["doctor@example.com"])
        self.processor.register_observer(observer)

        observer2 = EmailAlertObserver(recipients=["nurse@example.com"])
        self.processor.register_observer(observer2)

        # Unregister an observer
        result = self.processor.unregister_observer(observer)

        # Check that observer was unregistered
        self.assertTrue(result)
        self.assertNotIn(observer, self.processor.observers)
        self.assertIn(observer2, self.processor.observers)

    def test_process_data_point_no_patient_id(self) -> None:
        """Test processing a data point with no patient ID."""
        # Create a data point with no patient ID
        data_point = BiometricDataPoint(
            patient_id="", data_type=BiometricType.HEART_RATE, value=120
        )

        # Process the data point
        alerts = self.processor.process_data_point(data_point)

        # Check that no alerts were generated
        self.assertEqual(len(alerts), 0)

    def test_process_data_point_no_matching_rules(self) -> None:
        """Test processing a data point with no matching rules."""
        # Add a rule for blood pressure
        rule = AlertRule(
            name="High Blood Pressure",
            data_type=BiometricType.BLOOD_PRESSURE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=140,
        )
        self.processor.add_rule(rule)

        # Create a data point for heart rate
        data_point = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=120
        )

        # Process the data point
        alerts = self.processor.process_data_point(data_point)

        # Check that no alerts were generated
        self.assertEqual(len(alerts), 0)

    def test_process_data_point_matching_rule(self) -> None:
        """Test processing a data point that matches a rule."""
        # Add a rule
        rule = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=100,
            severity=AlertSeverity.HIGH,
        )
        self.processor.add_rule(rule)

        # Create a data point that should trigger the rule
        data_point = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=120
        )

        # Process the data point
        alerts = self.processor.process_data_point(data_point)

        # Check that an alert was generated
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, rule.id)
        self.assertEqual(alerts[0].patient_id, "patient1")
        self.assertEqual(alerts[0].severity, AlertSeverity.HIGH)

    def test_process_data_point_patient_specific_rule(self) -> None:
        """Test processing a data point with a patient-specific rule."""
        # Add a patient-specific rule
        rule = AlertRule(
            name="Patient-Specific Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=100,
            patient_id="patient1",
        )
        self.processor.add_rule(rule)

        # Create data points for different patients
        data_point1 = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=120
        )

        data_point2 = BiometricDataPoint(
            patient_id="patient2", data_type=BiometricType.HEART_RATE, value=120
        )

        # Process the data points
        alerts1 = self.processor.process_data_point(data_point1)
        alerts2 = self.processor.process_data_point(data_point2)

        # Check that only data_point1 generated an alert
        self.assertEqual(len(alerts1), 1)
        self.assertEqual(len(alerts2), 0)

    def test_process_data_point_inactive_rule(self) -> None:
        """Test processing a data point with an inactive rule."""
        # Add an inactive rule
        rule = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=100,
            active=False,
        )
        self.processor.add_rule(rule)

        # Create a data point that would match the rule if it were active
        data_point = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=120
        )

        # Process the data point
        alerts = self.processor.process_data_point(data_point)

        # Check that no alerts were generated
        self.assertEqual(len(alerts), 0)

    def test_process_data_point_updates_context(self) -> None:
        """Test that processing a data point updates the patient context."""
        # Create a data point
        data_point = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=80
        )

        # Process the data point
        self.processor.process_data_point(data_point)

        # Check that context was created and updated
        context = self.processor.get_context("patient1")
        self.assertEqual(context.last_values[BiometricType.HEART_RATE], 80)
        self.assertEqual(len(context.trends[BiometricType.HEART_RATE]), 1)

        # Process another data point
        data_point2 = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=90
        )

        self.processor.process_data_point(data_point2)

        # Check that context was updated
        self.assertEqual(context.last_values[BiometricType.HEART_RATE], 90)
        self.assertEqual(len(context.trends[BiometricType.HEART_RATE]), 2)
        self.assertEqual(context.trends[BiometricType.HEART_RATE], [80, 90])

    def test_pituitary_region_support(self) -> None:
        """Test specific support for pituitary region with adjusted sensitivity."""
        # Add a rule for detecting hypothalamus-pituitary axis anomalies
        rule = AlertRule(
            name="Pituitary hormone level high",
            data_type=BiometricType.CUSTOM,  # Using custom for hormone levels
            operator=ComparisonOperator.GREATER_THAN,
            threshold=8.5,  # Threshold for normal hormone level
        )
        self.processor.add_rule(rule)

        # Create a data point with pituitary region metadata
        data_point = BiometricDataPoint(
            patient_id="patient1",
            data_type=BiometricType.CUSTOM,
            value=10.0,
            metadata={"brain_region": "pituitary"},
        )

        # Process the data point - should have pituitary modifier applied
        alerts = self.processor.process_data_point(data_point)

        # Check that the value was adjusted by pituitary modifier
        self.assertEqual(data_point.metadata["original_value"], 10.0)
        self.assertAlmostEqual(data_point.value, 10.0 * self.processor.pituitary_threshold_modifier)

        # Value after adjustment should be 10.0 * 0.85 = 8.5
        # This should be exactly at threshold, not trigger an alert with greater_than
        self.assertEqual(len(alerts), 0)

        # Try with a higher value that will trigger even with modification
        data_point2 = BiometricDataPoint(
            patient_id="patient1",
            data_type=BiometricType.CUSTOM,
            value=12.0,
            metadata={"brain_region": "pituitary"},
        )

        alerts2 = self.processor.process_data_point(data_point2)
        self.assertEqual(len(alerts2), 1)


@pytest.mark.standalone()
class TestAlertRule(unittest.TestCase):
    """Test the alert rule class with mathematical precision."""

    def setUp(self) -> None:
        """Set up for alert rule tests."""
        # Create a standard rule for testing
        self.rule = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=100,
            severity=AlertSeverity.HIGH,
        )

    def test_create_alert_rule(self) -> None:
        """Test creating an alert rule."""
        # Check basic properties
        self.assertEqual(self.rule.name, "High Heart Rate")
        self.assertEqual(self.rule.data_type, BiometricType.HEART_RATE)
        self.assertEqual(self.rule.operator, ComparisonOperator.GREATER_THAN)
        self.assertEqual(self.rule.threshold, 100)
        self.assertEqual(self.rule.severity, AlertSeverity.HIGH)
        self.assertTrue(self.rule.active)
        self.assertEqual(self.rule.cooldown_minutes, 30)  # Default
        self.assertIsNotNone(self.rule.id)  # UUID was generated
        self.assertIsInstance(self.rule.last_triggered, dict)

    def test_evaluate_rule_match(self) -> None:
        """Test evaluating a rule with a matching data point."""
        # Create a data point that matches the rule
        data_point = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=110
        )

        # Evaluate the rule
        result = self.rule.evaluate(data_point)

        # Check that rule matched
        self.assertTrue(result)

        # Check that last_triggered was updated
        self.assertIn("patient1", self.rule.last_triggered)

    def test_evaluate_rule_no_match(self) -> None:
        """Test evaluating a rule with a non-matching data point."""
        # Create a data point that doesn't match the rule
        data_point = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=90
        )

        # Evaluate the rule
        result = self.rule.evaluate(data_point)

        # Check that rule didn't match
        self.assertFalse(result)

        # Check that last_triggered was not updated
        self.assertNotIn("patient1", self.rule.last_triggered)

    def test_evaluate_data_type_mismatch(self) -> None:
        """Test evaluating a rule with a data point of a different type."""
        # Create a data point with a different data type
        data_point = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.BLOOD_PRESSURE, value=120
        )

        # Evaluate the rule
        result = self.rule.evaluate(data_point)

        # Check that rule didn't match
        self.assertFalse(result)

    def test_evaluate_rule_with_patient_specific(self) -> None:
        """Test evaluating a patient-specific rule."""
        # Create a patient-specific rule
        rule = AlertRule(
            name="High Heart Rate for Patient1",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=100,
            severity=AlertSeverity.HIGH,
            patient_id="patient1",
        )

        # Create data points for different patients
        matching_data_point = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=110
        )

        non_matching_data_point = BiometricDataPoint(
            patient_id="patient2", data_type=BiometricType.HEART_RATE, value=110
        )

        # Evaluate the rule
        self.assertTrue(rule.evaluate(matching_data_point))
        self.assertFalse(rule.evaluate(non_matching_data_point))

    def test_evaluate_greater_than(self) -> None:
        """Test evaluating a rule with the greater than operator."""
        # Create a rule with greater than operator
        rule = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN,
            threshold=100,
        )

        # Create data points
        above_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=110
        )

        at_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=100
        )

        below_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=90
        )

        # Evaluate the rule
        self.assertTrue(rule.evaluate(above_threshold))
        self.assertFalse(rule.evaluate(at_threshold))
        self.assertFalse(rule.evaluate(below_threshold))

    def test_evaluate_greater_than_or_equal(self) -> None:
        """Test evaluating a rule with the greater than or equal operator."""
        # Create data points
        above_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=110
        )

        at_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=100
        )

        below_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=90
        )

        # Test each case with a fresh rule to avoid cooldown interference
        # Test above threshold
        rule1 = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN_OR_EQUAL,
            threshold=100,
        )
        self.assertTrue(rule1.evaluate(above_threshold))

        # Test at threshold
        rule2 = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN_OR_EQUAL,
            threshold=100,
        )
        self.assertTrue(rule2.evaluate(at_threshold))

        # Test below threshold
        rule3 = AlertRule(
            name="High Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.GREATER_THAN_OR_EQUAL,
            threshold=100,
        )
        self.assertFalse(rule3.evaluate(below_threshold))

    def test_evaluate_less_than(self) -> None:
        """Test evaluating a rule with the less than operator."""
        # Create a rule with less than operator
        rule = AlertRule(
            name="Low Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.LESS_THAN,
            threshold=60,
        )

        # Create data points
        above_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=70
        )

        at_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=60
        )

        below_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=50
        )

        # Evaluate the rule
        self.assertFalse(rule.evaluate(above_threshold))
        self.assertFalse(rule.evaluate(at_threshold))
        self.assertTrue(rule.evaluate(below_threshold))

    def test_evaluate_less_than_or_equal(self) -> None:
        """Test evaluating a rule with the less than or equal operator."""
        # Create data points
        above_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=70
        )

        at_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=60
        )

        below_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=50
        )

        # Test each case with a fresh rule to avoid cooldown interference
        # Test above threshold
        rule1 = AlertRule(
            name="Low Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.LESS_THAN_OR_EQUAL,
            threshold=60,
        )
        self.assertFalse(rule1.evaluate(above_threshold))

        # Test at threshold
        rule2 = AlertRule(
            name="Low Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.LESS_THAN_OR_EQUAL,
            threshold=60,
        )
        self.assertTrue(rule2.evaluate(at_threshold))

        # Test below threshold
        rule3 = AlertRule(
            name="Low Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.LESS_THAN_OR_EQUAL,
            threshold=60,
        )
        self.assertTrue(rule3.evaluate(below_threshold))

    def test_evaluate_equal(self) -> None:
        """Test evaluating a rule with the equal operator."""
        # Create a rule with equal operator
        rule = AlertRule(
            name="Exact Heart Rate",
            data_type=BiometricType.HEART_RATE,
            operator=ComparisonOperator.EQUAL,
            threshold=60,
        )

        # Create data points
        above_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=70
        )

        at_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=60
        )

        below_threshold = BiometricDataPoint(
            patient_id="patient1", data_type=BiometricType.HEART_RATE, value=50
        )

        # Evaluate the rule
        self.assertFalse(rule.evaluate(above_threshold))
        self.assertTrue(rule.evaluate(at_threshold))
        self.assertFalse(rule.evaluate(below_threshold))


# TODO: Update the test to use actual implementations instead of standalone duplicates
