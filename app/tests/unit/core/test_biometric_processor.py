"""
Unit tests for the BiometricEventProcessor.

These tests verify the actual implementation of the BiometricEventProcessor
using the proper domain models and service classes.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest

from app.domain.entities.biometric_twin import BiometricDataPoint
from app.domain.exceptions.base_exceptions import ValidationError
from app.domain.services.biometric_event_processor import (
    AlertObserver,
    AlertPriority,
    AlertRule,
    BiometricAlert,
    BiometricEventProcessor,
    ClinicalRuleEngine,
    EmailAlertObserver,
    InAppAlertObserver,
    SMSAlertObserver,
)
from app.domain.utils.datetime_utils import UTC


@pytest.fixture
def sample_patient_id():
    """Return a sample patient UUID for testing."""
    return UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def sample_clinician_id():
    """Return a sample clinician UUID for testing."""
    return UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def sample_data_point(sample_patient_id):
    """Return a sample biometric data point for testing."""
    return BiometricDataPoint(
        data_id=UUID("00000000-0000-0000-0000-000000000002"),
        patient_id=sample_patient_id,
        data_type="heart_rate",
        value=120.0,
        timestamp=datetime.now(UTC),
        source="apple_watch",
        metadata={"activity": "resting"},
        confidence=0.95,
    )


@pytest.fixture
def sample_rule(sample_clinician_id):
    """Return a sample alert rule for testing."""
    return AlertRule(
        rule_id="test-rule-1",
        name="High Heart Rate",
        description="Alert when heart rate exceeds 100 bpm",
        priority=AlertPriority.WARNING,
        condition={"data_type": "heart_rate", "operator": ">", "threshold": 100.0},
        created_by=sample_clinician_id,
    )


@pytest.fixture
def mock_observer():
    """Return a mock observer for testing."""
    observer = MagicMock(spec=AlertObserver)
    observer.notify = MagicMock()
    return observer


@pytest.fixture
def processor():
    """Return a BiometricEventProcessor instance for testing."""
    return BiometricEventProcessor()


class TestAlertRule:
    """Tests for the AlertRule class."""

    def test_init_valid(self, sample_clinician_id) -> None:
        """Test initializing an AlertRule with valid parameters."""
        rule = AlertRule(
            rule_id="test-rule-1",
            name="High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={"data_type": "heart_rate", "operator": ">", "threshold": 100.0},
            created_by=sample_clinician_id,
        )

        assert rule.rule_id == "test-rule-1"
        assert rule.name == "High Heart Rate"
        assert rule.description == "Alert when heart rate exceeds 100 bpm"
        assert rule.priority == AlertPriority.WARNING
        assert rule.condition["data_type"] == "heart_rate"
        assert rule.condition["operator"] == ">"
        assert rule.condition["threshold"] == 100.0
        assert rule.created_by == sample_clinician_id

    def test_init_invalid_condition(self, sample_clinician_id) -> None:
        """Test initializing an AlertRule with an invalid condition."""
        with pytest.raises(ValidationError):
            AlertRule(
                rule_id="test-rule-1",
                name="High Heart Rate",
                description="Alert when heart rate exceeds 100 bpm",
                priority=AlertPriority.WARNING,
                condition={
                    "data_type": "heart_rate",
                    "operator": "BAD_OPERATOR",  # This will trigger ValidationError
                    "threshold": 100,
                },
                created_by=sample_clinician_id,
            )

    def test_evaluate_true(self, sample_data_point, sample_rule) -> None:
        """Test evaluating a rule that should return True."""
        # The sample data point has heart_rate=120, which is > 100
        result = sample_rule.evaluate(sample_data_point)
        assert result is True

    def test_evaluate_false(self, sample_data_point, sample_rule) -> None:
        """Test evaluating a rule that should return False."""
        # Modify the data point to have a heart rate below the threshold
        sample_data_point.value = 90.0
        result = sample_rule.evaluate(sample_data_point)
        assert result is False

    def test_evaluate_different_data_type(self, sample_data_point, sample_rule) -> None:
        """Test evaluating a rule with a different data type."""
        # Modify the data point to have a different data type
        sample_data_point.data_type = "blood_pressure"
        result = sample_rule.evaluate(sample_data_point)
        assert result is False


class TestBiometricEventProcessor:
    """Tests for the BiometricEventProcessor class."""

    def test_initialize(self, processor) -> None:
        """Test initialization of the BiometricEventProcessor."""
        # In the actual implementation, rules is a dictionary, not a list
        assert isinstance(processor.rules, dict)
        assert len(processor.rules) == 0

    def test_add_rule(self, processor, sample_rule) -> None:
        """Test adding a rule to the processor using add_rule method."""
        rule1 = sample_rule
        rule2 = AlertRule(
            rule_id="test-rule-2",
            name="Low Heart Rate",
            description="Alert when heart rate drops below 50 bpm",
            priority=AlertPriority.WARNING,
            condition={"data_type": "heart_rate", "operator": "<", "threshold": 50.0},
            created_by=rule1.created_by,
        )

        processor.add_rule(rule1)
        processor.add_rule(rule2)

        # Actual implementation stores rules in a dict with rule_id as key
        assert rule1.rule_id in processor.rules
        assert rule2.rule_id in processor.rules
        assert processor.rules[rule1.rule_id] == rule1
        assert processor.rules[rule2.rule_id] == rule2

    def test_register_rule(self, processor, sample_rule) -> None:
        """Test registering a rule with the processor."""
        processor.register_rule(sample_rule)
        assert sample_rule.rule_id in processor.rules
        assert processor.rules[sample_rule.rule_id] == sample_rule

    def test_register_observer(self, processor, mock_observer) -> None:
        """Test registering an observer with the processor."""
        processor.register_observer(mock_observer)
        # Assert observer is in all priorities since no specific priorities were specified
        assert mock_observer in processor.observers[AlertPriority.URGENT]
        assert mock_observer in processor.observers[AlertPriority.WARNING]
        assert mock_observer in processor.observers[AlertPriority.INFORMATIONAL]

    def test_process_data_point_no_alert(self, processor, sample_data_point, sample_rule) -> None:
        """Test processing a data point that doesn't trigger an alert."""
        # Modify the data point to have a heart rate below the threshold
        sample_data_point.value = 90.0
        processor.register_rule(sample_rule)

        # Process the data point
        alerts = processor.process_data_point(sample_data_point)

        # Verify no alerts were generated
        assert len(alerts) == 0

    def test_process_data_point_with_alert(
        self, processor, sample_data_point, sample_rule, mock_observer
    ) -> None:
        """Test processing a data point that triggers an alert."""
        processor.register_observer(mock_observer)
        processor.register_rule(sample_rule)

        # Process the data point (value=120, which is > 100)
        alerts = processor.process_data_point(sample_data_point)

        # Verify an alert was generated
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.rule_id == sample_rule.rule_id
        assert alert.patient_id == sample_data_point.patient_id
        assert alert.data_point == sample_data_point

        # Verify the observer was notified
        mock_observer.notify.assert_called_once()


class TestAlertObservers:
    """Tests for the various AlertObserver implementations."""

    def test_in_app_observer(self, sample_data_point, sample_rule) -> None:
        """Test the InAppAlertObserver."""
        mock_notification_service = MagicMock()
        observer = InAppAlertObserver(notification_service=mock_notification_service)

        # Create an alert using the proper constructor signature for BiometricAlert
        alert = BiometricAlert(
            patient_id=sample_data_point.patient_id,
            rule_id=sample_rule.rule_id,
            rule_name=sample_rule.name,
            priority=sample_rule.priority,
            data_point=sample_data_point,
            message="Test alert message",
        )

        # Replace the send_in_app_notification method with a mock to avoid making actual calls
        with patch.object(observer, "send_in_app_notification") as mock_send:
            observer.notify(alert)
            mock_send.assert_called_once_with(alert)

    def test_email_observer(self, sample_data_point, sample_rule) -> None:
        """Test the EmailAlertObserver."""
        mock_email_service = MagicMock()
        observer = EmailAlertObserver(email_service=mock_email_service)

        # Create alerts with different priorities
        urgent_alert = BiometricAlert(
            patient_id=sample_data_point.patient_id,
            rule_id=sample_rule.rule_id,
            rule_name=sample_rule.name,
            priority=AlertPriority.URGENT,
            data_point=sample_data_point,
            message="Urgent alert",
        )

        # Replace the send_email method with a mock
        with patch.object(observer, "send_email") as mock_send:
            observer.notify(urgent_alert)
            mock_send.assert_called_once_with(urgent_alert)

    def test_sms_observer(self, sample_data_point, sample_rule) -> None:
        """Test the SMSAlertObserver."""
        mock_sms_service = MagicMock()
        observer = SMSAlertObserver(sms_service=mock_sms_service)

        # Create an urgent alert to trigger SMS
        alert = BiometricAlert(
            patient_id=sample_data_point.patient_id,
            rule_id=sample_rule.rule_id,
            rule_name=sample_rule.name,
            priority=AlertPriority.URGENT,
            data_point=sample_data_point,
            message="Urgent test alert",
        )

        # Mock the send_sms method
        with patch.object(observer, "send_sms") as mock_send:
            observer.notify(alert)
            mock_send.assert_called_once_with(alert)


class TestClinicalRuleEngine:
    """Tests for the ClinicalRuleEngine class."""

    def test_register_rule_template(self) -> None:
        """Test registering a rule template."""
        engine = ClinicalRuleEngine()
        template_id = "high-heart-rate"
        template = {
            "name": "High Heart Rate",
            "description": "Alert when heart rate exceeds threshold",
            "priority": AlertPriority.WARNING,
            "condition": {
                "data_type": "heart_rate",
                "operator": ">",
                "threshold": "${threshold}",
            },
            "default_threshold": 100.0,
        }

        engine.register_rule_template(template, template_id)
        assert template_id in engine.rule_templates
        assert engine.rule_templates[template_id] == template

    def test_create_rule_from_template(self, sample_clinician_id) -> None:
        """Test creating a rule from a template."""
        engine = ClinicalRuleEngine()
        template_id = "high-heart-rate"
        template = {
            "name": "High Heart Rate",
            "description": "Alert when heart rate exceeds threshold",
            "priority": AlertPriority.WARNING,
            "condition": {
                "data_type": "heart_rate",
                "operator": ">",
                "threshold": "${threshold}",
            },
            "default_threshold": 100.0,
        }

        engine.register_rule_template(template, template_id)

        # Create a rule from the template
        parameters = {"threshold": 120.0}
        rule_id = "custom-heart-rate-rule"
        rule = engine.create_rule_from_template(
            template_id=template_id,
            rule_id=rule_id,
            parameters=parameters,
            created_by=sample_clinician_id,
        )

        # Verify the rule was created correctly
        assert rule.name == template["name"]
        assert rule.description == template["description"]
        assert rule.priority == template["priority"]
        assert rule.condition["data_type"] == template["condition"]["data_type"]
        assert rule.condition["operator"] == template["condition"]["operator"]
        assert rule.condition["threshold"] == parameters["threshold"]  # Overridden
        assert rule.created_by == sample_clinician_id

    def test_create_rule_from_nonexistent_template(self, sample_clinician_id) -> None:
        """Test creating a rule from a nonexistent template."""
        engine = ClinicalRuleEngine()
        with pytest.raises(ValueError):
            engine.create_rule_from_template(
                template_id="nonexistent",
                rule_id="test-nonexistent-rule",
                parameters={},
                created_by=sample_clinician_id,
            )
