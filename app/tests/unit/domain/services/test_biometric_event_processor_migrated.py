"""
Migrated tests for the BiometricEventProcessor from standalone to proper unit tests.

These tests verify that the BiometricEventProcessor correctly processes
biometric data points, evaluates rules, and notifies observers.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest

from app.domain.entities.biometric_twin import BiometricDataPoint
from app.domain.exceptions import ValidationError
from app.domain.services.biometric_event_processor import (
    AlertObserver,
    AlertPriority,
    AlertRule,
    BiometricAlert,
    BiometricEventProcessor,
    EmailAlertObserver,
    InAppAlertObserver,
    SMSAlertObserver,
)
from app.domain.utils.datetime_utils import UTC


@pytest.fixture
def sample_patient_id():
    """Create a sample patient ID."""
    return UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def sample_clinician_id():
    """Create a sample clinician ID."""
    return UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def sample_data_point(sample_patient_id):
    """Create a sample biometric data point."""
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
    """Create a sample alert rule."""
    return AlertRule(
        rule_id="test-rule-1",
        name="High Heart Rate",
        description="Alert when heart rate exceeds 100 bpm",
        priority=AlertPriority.WARNING,
        condition={"data_type": "heart_rate", "operator": ">", "threshold": 100.0},
        created_by=sample_clinician_id,
        is_active=True,
    )


@pytest.fixture
def mock_observer():
    """Create a mock observer."""
    observer = MagicMock(spec=AlertObserver)
    observer.notify = MagicMock()
    return observer


# Migrated from standalone test - TestBiometricEventProcessor
class TestBiometricEventProcessor:
    """Tests for the BiometricEventProcessor."""

    def test_add_rule(self, sample_rule):
        """Test that add_rule adds a rule to the processor."""
        processor = BiometricEventProcessor()
        processor.add_rule(sample_rule)

        assert sample_rule.rule_id in processor.rules
        assert processor.rules[sample_rule.rule_id] == sample_rule

    def test_remove_rule(self, sample_rule):
        """Test that remove_rule removes a rule from the processor."""
        processor = BiometricEventProcessor()
        processor.add_rule(sample_rule)
        processor.remove_rule(sample_rule.rule_id)

        assert sample_rule.rule_id not in processor.rules

    def test_register_observer(self, mock_observer):
        """Test that register_observer registers an observer for specific priorities."""
        processor = BiometricEventProcessor()
        processor.register_observer(mock_observer, [AlertPriority.WARNING])

        assert mock_observer in processor.observers[AlertPriority.WARNING]
        assert mock_observer not in processor.observers[AlertPriority.URGENT]
        assert mock_observer not in processor.observers[AlertPriority.INFORMATIONAL]

    def test_unregister_observer(self, mock_observer):
        """Test that unregister_observer unregisters an observer from all priorities."""
        processor = BiometricEventProcessor()
        processor.register_observer(
            mock_observer, [AlertPriority.WARNING, AlertPriority.URGENT]
        )
        processor.unregister_observer(mock_observer)

        assert mock_observer not in processor.observers[AlertPriority.WARNING]
        assert mock_observer not in processor.observers[AlertPriority.URGENT]
        assert mock_observer not in processor.observers[AlertPriority.INFORMATIONAL]

    def test_process_data_point_no_patient_id(self):
        """Test that process_data_point raises an error if the data point has no patient ID."""
        processor = BiometricEventProcessor()
        data_point = BiometricDataPoint(
            data_id=UUID("00000000-0000-0000-0000-000000000002"),
            patient_id=None,  # No patient ID
            data_type="heart_rate",
            value=120.0,
            timestamp=datetime.now(UTC),
            source="apple_watch",
            metadata={"activity": "resting"},
            confidence=0.95,
        )

        with pytest.raises(ValidationError):
            processor.process_data_point(data_point)

    def test_process_data_point_no_matching_rules(self, sample_data_point):
        """Test that process_data_point returns no alerts if no rules match."""
        processor = BiometricEventProcessor()
        rule = AlertRule(
            rule_id="test-rule-1",
            name="Low Heart Rate",
            description="Alert when heart rate is below 50 bpm",
            priority=AlertPriority.WARNING,
            condition={"data_type": "heart_rate", "operator": "<", "threshold": 50.0},
            created_by=UUID("00000000-0000-0000-0000-000000000001"),
            is_active=True,
        )
        processor.add_rule(rule)

        alerts = processor.process_data_point(sample_data_point)

        assert len(alerts) == 0

    def test_process_data_point_matching_rule(
        self, sample_data_point, sample_rule, mock_observer
    ):
        """Test that process_data_point returns alerts for matching rules and notifies observers."""
        processor = BiometricEventProcessor()
        processor.add_rule(sample_rule)
        processor.register_observer(mock_observer, [AlertPriority.WARNING])

        alerts = processor.process_data_point(sample_data_point)

        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, BiometricAlert)
        assert alert.patient_id == sample_data_point.patient_id
        assert alert.rule_id == sample_rule.rule_id
        assert alert.priority == sample_rule.priority
        assert alert.data_point == sample_data_point

        mock_observer.notify.assert_called_once()
        call_args, _ = mock_observer.notify.call_args
        assert call_args[0] == alert

    def test_process_data_point_patient_specific_rule(
        self, sample_data_point, sample_rule, sample_clinician_id
    ):
        """Test that process_data_point only applies patient-specific rules to the right patient."""
        processor = BiometricEventProcessor()

        # Add a patient-specific rule for a different patient
        other_patient_id = UUID("99999999-9999-9999-9999-999999999999")
        patient_specific_rule = AlertRule(
            rule_id="test-rule-2",
            name="Patient-Specific High Heart Rate",
            description="Alert when heart rate exceeds 90 bpm for a specific patient",
            priority=AlertPriority.WARNING,
            condition={"data_type": "heart_rate", "operator": ">", "threshold": 90.0},
            created_by=sample_clinician_id,
            patient_id=other_patient_id,
            is_active=True,
        )
        processor.add_rule(patient_specific_rule)

        # Add a general rule (no patient_id)
        general_rule = AlertRule(
            rule_id="test-rule-general",
            name="General High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={"data_type": "heart_rate", "operator": ">", "threshold": 100.0},
            created_by=sample_clinician_id,
            patient_id=None,
            is_active=True,
        )
        processor.add_rule(general_rule)

        # Process a data point for the sample patient (heart rate 120)
        alerts = processor.process_data_point(sample_data_point)

        # Should only match the general rule, not the one for other_patient_id
        assert len(alerts) == 1
        assert alerts[0].rule_id == general_rule.rule_id

    def test_process_data_point_inactive_rule(self, sample_data_point, sample_rule):
        """Test that process_data_point ignores inactive rules."""
        processor = BiometricEventProcessor()
        sample_rule.is_active = False
        processor.add_rule(sample_rule)

        alerts = processor.process_data_point(sample_data_point)

        assert len(alerts) == 0

    # Migrated from standalone tests - additional test cases

    def test_evaluate_greater_than_or_equal(self, sample_rule, sample_data_point):
        """Test evaluation of 'greater than or equal to' operator."""
        sample_clinician_id = UUID("00000000-0000-0000-0000-000000000001")

        # Create rule with 'greater than or equal to' operator and value exactly equal to data point
        rule = AlertRule(
            rule_id="test-rule-equal",
            name="Heart Rate Threshold",
            description="Alert when heart rate equals or exceeds threshold",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": ">=",
                "threshold": 120.0,  # Exactly equal to sample data point value
            },
            created_by=sample_clinician_id,
            is_active=True,
        )

        # Should trigger because 120 >= 120
        assert rule.evaluate(sample_data_point)

        # Modify the rule threshold to be higher
        rule.condition["threshold"] = 121.0

        # Should not trigger because 120 is not >= 121
        assert not rule.evaluate(sample_data_point)

        # Modify the rule threshold to be lower
        rule.condition["threshold"] = 119.0

        # Should trigger because 120 >= 119
        assert rule.evaluate(sample_data_point)


# Migrated from standalone test - TestAlertRule
class TestAlertRule:
    """Tests for the AlertRule class."""

    def test_evaluate_greater_than(self, sample_rule, sample_data_point):
        """Test evaluation of 'greater than' operator."""
        # Modify the rule to use the '>' operator
        sample_rule.condition["operator"] = ">"
        sample_rule.condition["threshold"] = 119.0

        # Should trigger because 120 > 119
        assert sample_rule.evaluate(sample_data_point)

        # Modify the threshold to equal the data point value
        sample_rule.condition["threshold"] = 120.0

        # Should not trigger because 120 is not > 120
        assert not sample_rule.evaluate(sample_data_point)

        # Modify the threshold to be greater than the data point value
        sample_rule.condition["threshold"] = 121.0

        # Should not trigger because 120 is not > 121
        assert not sample_rule.evaluate(sample_data_point)
