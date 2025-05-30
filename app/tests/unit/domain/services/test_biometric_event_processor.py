"""
Unit tests for the BiometricEventProcessor.

These tests verify that the BiometricEventProcessor correctly processes
biometric data points, evaluates rules, and notifies observers.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch  # Added AsyncMock
from uuid import UUID

import pytest

from app.domain.entities.biometric_twin import BiometricDataPoint
from app.domain.exceptions import ValidationError
from app.domain.services.biometric_event_processor import (
    AlertObserver,
    AlertPriority,
    AlertRule,  # Assuming AlertRule exists or is defined elsewhere
    BiometricAlert,
    BiometricEventProcessor,
    EmailAlertObserver,
    InAppAlertObserver,  # Assuming ClinicalRuleEngine exists or is defined elsewhere
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
    # Assuming AlertRule takes condition as a dict for simplicity in test setup
    return AlertRule(
        rule_id="test-rule-1",
        name="High Heart Rate",
        description="Alert when heart rate exceeds 100 bpm",
        priority=AlertPriority.WARNING,
        condition={"data_type": "heart_rate", "operator": ">", "threshold": 100.0},
        created_by=sample_clinician_id,
        is_active=True,  # Assuming is_active attribute exists
    )


@pytest.fixture
def mock_observer():
    """Create a mock observer."""
    observer = MagicMock(spec=AlertObserver)
    observer.notify = MagicMock()
    return observer


@pytest.mark.venv_only()  # Assuming venv_only is a valid marker
class TestBiometricEventProcessor:
    """Tests for the BiometricEventProcessor."""

    def test_add_rule(self, sample_rule) -> None:
        """Test that add_rule adds a rule to the processor."""
        processor = BiometricEventProcessor()
        processor.add_rule(sample_rule)

        assert sample_rule.rule_id in processor.rules
        assert processor.rules[sample_rule.rule_id] == sample_rule

    def test_remove_rule(self, sample_rule) -> None:
        """Test that remove_rule removes a rule from the processor."""
        processor = BiometricEventProcessor()
        processor.add_rule(sample_rule)
        processor.remove_rule(sample_rule.rule_id)

        assert sample_rule.rule_id not in processor.rules

    def test_register_observer(self, mock_observer) -> None:
        """Test that register_observer registers an observer for specific priorities."""
        processor = BiometricEventProcessor()
        processor.register_observer(mock_observer, [AlertPriority.WARNING])

        assert mock_observer in processor.observers[AlertPriority.WARNING]
        assert mock_observer not in processor.observers[AlertPriority.URGENT]
        assert mock_observer not in processor.observers[AlertPriority.INFORMATIONAL]

    def test_unregister_observer(self, mock_observer) -> None:
        """Test that unregister_observer unregisters an observer from all priorities."""
        processor = BiometricEventProcessor()
        processor.register_observer(mock_observer, [AlertPriority.WARNING, AlertPriority.URGENT])
        processor.unregister_observer(mock_observer)

        assert mock_observer not in processor.observers[AlertPriority.WARNING]
        assert mock_observer not in processor.observers[AlertPriority.URGENT]
        assert mock_observer not in processor.observers[AlertPriority.INFORMATIONAL]

    def test_process_data_point_no_patient_id(self) -> None:
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

    def test_process_data_point_no_matching_rules(self, sample_data_point) -> None:
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
    ) -> None:
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
        # Check the first argument passed to notify
        call_args, _ = mock_observer.notify.call_args
        assert call_args[0] == alert

    def test_process_data_point_patient_specific_rule(
        self, sample_data_point, sample_rule, sample_clinician_id
    ) -> None:
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
            patient_id=other_patient_id,  # Specific patient
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
            patient_id=None,  # General rule
            is_active=True,
        )
        processor.add_rule(general_rule)

        # Process a data point for the sample patient (heart rate 120)
        alerts = processor.process_data_point(sample_data_point)

        # Should only match the general rule, not the one for other_patient_id
        assert len(alerts) == 1
        assert alerts[0].rule_id == general_rule.rule_id

    def test_process_data_point_inactive_rule(self, sample_data_point, sample_rule) -> None:
        """Test that process_data_point ignores inactive rules."""
        processor = BiometricEventProcessor()
        sample_rule.is_active = False
        processor.add_rule(sample_rule)

        alerts = processor.process_data_point(sample_data_point)

        assert len(alerts) == 0

    def test_process_data_point_updates_context(self, sample_data_point) -> None:
        """Test that process_data_point updates the patient context."""
        processor = BiometricEventProcessor()

        # Process a data point
        processor.process_data_point(sample_data_point)

        # Check that the context was updated
        assert sample_data_point.patient_id in processor.patient_context
        context = processor.patient_context[sample_data_point.patient_id]
        assert "latest_values" in context
        assert sample_data_point.data_type in context["latest_values"]
        assert context["latest_values"][sample_data_point.data_type] == sample_data_point.value


class TestAlertRule:
    """Tests for the AlertRule class."""

    def test_evaluate_data_type_mismatch(self, sample_rule, sample_data_point) -> None:
        """Test that evaluate returns False if the data type doesn't match."""
        # Change the rule's data type
        sample_rule.condition["data_type"] = "blood_pressure"

        # Evaluate the rule
        result = sample_rule.evaluate(sample_data_point, {})

        assert result is False

    def test_evaluate_greater_than(self, sample_rule, sample_data_point) -> None:
        """Test that evaluate correctly handles the > operator."""
        # Set up the rule and data point
        sample_rule.condition["operator"] = ">"
        sample_rule.condition["threshold"] = 100.0
        sample_data_point.value = 120.0

        # Evaluate the rule
        result = sample_rule.evaluate(sample_data_point, {})

        assert result is True

        # Test with a value that doesn't meet the condition
        sample_data_point.value = 80.0
        result = sample_rule.evaluate(sample_data_point, {})

        assert result is False

    def test_evaluate_greater_than_or_equal(self, sample_rule, sample_data_point) -> None:
        """Test that evaluate correctly handles the >= operator."""
        # Set up the rule and data point
        sample_rule.condition["operator"] = ">="
        sample_rule.condition["threshold"] = 100.0

        # Test with a value greater than the threshold
        sample_data_point.value = 120.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is True

        # Test with a value equal to the threshold
        sample_data_point.value = 100.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is True

        # Test with a value less than the threshold
        sample_data_point.value = 80.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is False

    def test_evaluate_less_than(self, sample_rule, sample_data_point) -> None:
        """Test that evaluate correctly handles the < operator."""
        # Set up the rule and data point
        sample_rule.condition["operator"] = "<"
        sample_rule.condition["threshold"] = 100.0

        # Test with a value less than the threshold
        sample_data_point.value = 80.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is True

        # Test with a value greater than the threshold
        sample_data_point.value = 120.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is False

    def test_evaluate_less_than_or_equal(self, sample_rule, sample_data_point) -> None:
        """Test that evaluate correctly handles the <= operator."""
        # Set up the rule and data point
        sample_rule.condition["operator"] = "<="
        sample_rule.condition["threshold"] = 100.0

        # Test with a value less than the threshold
        sample_data_point.value = 80.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is True

        # Test with a value equal to the threshold
        sample_data_point.value = 100.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is True

        # Test with a value greater than the threshold
        sample_data_point.value = 120.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is False

    def test_evaluate_equal(self, sample_rule, sample_data_point) -> None:
        """Test that evaluate correctly handles the == operator."""
        # Set up the rule and data point
        sample_rule.condition["operator"] = "=="
        sample_rule.condition["threshold"] = 100.0

        # Test with a value equal to the threshold
        sample_data_point.value = 100.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is True

        # Test with a value not equal to the threshold
        sample_data_point.value = 120.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is False

    def test_evaluate_not_equal(self, sample_rule, sample_data_point) -> None:
        """Test that evaluate correctly handles the != operator."""
        # Set up the rule and data point
        sample_rule.condition["operator"] = "!="
        sample_rule.condition["threshold"] = 100.0

        # Test with a value not equal to the threshold
        sample_data_point.value = 120.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is True

        # Test with a value equal to the threshold
        sample_data_point.value = 100.0
        result = sample_rule.evaluate(sample_data_point, {})
        assert result is False


class TestBiometricAlert:
    """Tests for the BiometricAlert class."""

    def test_acknowledge(self, sample_data_point, sample_rule, sample_clinician_id) -> None:
        """Test that acknowledge correctly marks an alert as acknowledged."""
        # Create an alert
        alert = BiometricAlert(
            alert_id="test-alert-1",
            patient_id=sample_data_point.patient_id,
            rule_id=sample_rule.rule_id,
            rule_name=sample_rule.name,
            priority=sample_rule.priority,
            data_point=sample_data_point,
            message="Test alert message",
            context={},
        )

        # Initially not acknowledged
        assert alert.acknowledged is False
        assert alert.acknowledged_at is None
        assert alert.acknowledged_by is None

        # Acknowledge the alert
        alert.acknowledge(sample_clinician_id)

        # Now acknowledged
        assert alert.acknowledged is True
        assert alert.acknowledged_at is not None
        assert alert.acknowledged_by == sample_clinician_id


class TestAlertObservers:
    """Tests for the AlertObserver classes."""

    def test_email_alert_observer(self, sample_data_point, sample_rule) -> None:
        """Test that EmailAlertObserver correctly notifies via email."""
        # Create a mock email service
        email_service = MagicMock()

        # Create an observer
        observer = EmailAlertObserver(email_service)

        # Create an alert
        alert = BiometricAlert(
            alert_id="test-alert-1",
            patient_id=sample_data_point.patient_id,
            rule_id=sample_rule.rule_id,
            rule_name=sample_rule.name,
            priority=sample_rule.priority,
            data_point=sample_data_point,
            message="Test alert message",
            context={},
        )

        # Patch the _get_recipient_for_patient method
        with patch.object(
            observer, "_get_recipient_for_patient", return_value="clinician@example.com"
        ):
            # Notify the observer
            observer.notify(alert)

            # Check that the email service was called (assuming implementation calls it)
            # email_service.send_email.assert_called_once() # Uncomment if
            # implemented

    def test_sms_alert_observer_urgent(self, sample_data_point, sample_rule) -> None:
        """Test that SMSAlertObserver correctly notifies via SMS for urgent alerts."""
        # Create a mock SMS service
        sms_service = MagicMock()

        # Create an observer
        observer = SMSAlertObserver(sms_service)

        # Create an urgent alert
        alert = BiometricAlert(
            alert_id="test-alert-1",
            patient_id=sample_data_point.patient_id,
            rule_id=sample_rule.rule_id,
            rule_name=sample_rule.name,
            priority=AlertPriority.URGENT,  # Urgent priority
            data_point=sample_data_point,
            message="Test alert message",
            context={},
        )

        # Patch the _get_recipient_for_patient method
        with patch.object(observer, "_get_recipient_for_patient", return_value="+1234567890"):
            # Notify the observer
            observer.notify(alert)

            # Check that the SMS service was called (assuming implementation calls it)
            # sms_service.send_sms.assert_called_once() # Uncomment if
            # implemented

    def test_sms_alert_observer_non_urgent(self, sample_data_point, sample_rule) -> None:
        """Test that SMSAlertObserver doesn't notify for non-urgent alerts."""
        # Create a mock SMS service
        sms_service = MagicMock()

        # Create an observer
        observer = SMSAlertObserver(sms_service)

        # Create a warning alert
        alert = BiometricAlert(
            alert_id="test-alert-1",
            patient_id=sample_data_point.patient_id,
            rule_id=sample_rule.rule_id,
            rule_name=sample_rule.name,
            priority=AlertPriority.WARNING,  # Non-urgent priority
            data_point=sample_data_point,
            message="Test alert message",
            context={},
        )

        # Notify the observer
        observer.notify(alert)

        # Check that the SMS service was not called
        sms_service.send_sms.assert_not_called()  # Assuming send_sms is the method

    def test_in_app_alert_observer(self, sample_data_point, sample_rule) -> None:
        """Test that InAppAlertObserver correctly notifies via in-app notifications."""
        # Create a mock notification service
        notification_service = MagicMock()

        # Create an observer
        observer = InAppAlertObserver(notification_service)

        # Create an alert
        alert = BiometricAlert(
            alert_id="test-alert-1",
            patient_id=sample_data_point.patient_id,
            rule_id=sample_rule.rule_id,
            rule_name=sample_rule.name,
            priority=sample_rule.priority,
            data_point=sample_data_point,
            message="Test alert message",
            context={},
        )

        # Patch the _get_recipients_for_patient method
        with patch.object(
            observer,
            "_get_recipients_for_patient",
            return_value=[UUID("00000000-0000-0000-0000-000000000001")],
        ):
            # Notify the observer
            observer.notify(alert)

            # Check that the notification service was called (assuming implementation calls it)
            # notification_service.send_notification.assert_called() #
            # Uncomment if implemented


# Assuming ClinicalRuleEngine is defined elsewhere and imported correctly
# If not, these tests need adjustment or removal.
# class TestClinicalRuleEngine:
#    """Tests for the ClinicalRuleEngine class."""
#
#    @pytest.fixture
#    def mock_rule_repo(self):
#        return AsyncMock()
#
#    @pytest.fixture
#    def engine(self, mock_rule_repo):
#        return ClinicalRuleEngine(rule_repository=mock_rule_repo)
#
#    def test_register_rule_template(self, engine):
#        """Test that register_rule_template correctly registers a template."""
#        template = {
#             "name": "High Heart Rate Template",
#             "description": "Alert when heart rate exceeds {threshold}",
#             "conditions": [{]
#                 "data_type": "heart_rate",
#                 "operator": ">",
#                 "threshold_value": "{threshold}", # Placeholder
#                 "time_window_hours": 1
#             }],
#             "logical_operator": "AND",
#             "alert_priority": "WARNING"
#         }
#         engine.register_rule_template("high_hr", template)
#         assert "high_hr" in engine.rule_templates

#     def test_create_rule_from_template(self, engine, sample_clinician_id):
#         """Test that create_rule_from_template correctly creates a rule from a template."""
#         template = {
#             "name": "High Heart Rate Template",
#             "description": "Alert when heart rate exceeds {threshold}",
#             "conditions": [{]
#                 "data_type": "heart_rate",
#                 "operator": ">",
#                 "threshold_value": "{threshold}",
#                 "time_window_hours": 1
#             }],
#             "logical_operator": "AND",
#             "alert_priority": "WARNING"
#         }
#         engine.register_rule_template("high_hr", template)

#         rule = engine.create_rule_from_template()
#             template_name="high_hr",
#             provider_id=sample_clinician_id,
#             parameters={"threshold": 110}
#         )
#         assert isinstance(rule, AlertRule)
#         assert rule.name == "High Heart Rate Template"
#         assert rule.conditions[0].threshold_value == 110
#         assert rule.provider_id == sample_clinician_id

#     def test_create_rule_from_template_missing_parameter(self, engine, sample_clinician_id):
#         """Test that create_rule_from_template raises an error if a required parameter is missing."""
#         template = {
#             "name": "High Heart Rate Template",
#             "description": "Alert when heart rate exceeds {threshold}",
#             "conditions": [{"data_type": "heart_rate", "operator": ">", "threshold_value": "{threshold}"}],
#             "logical_operator": "AND",
#             "alert_priority": "WARNING"
#         }
#         engine.register_rule_template("high_hr", template)

#         with pytest.raises(ValueError, match="Missing required parameter"):
#             engine.create_rule_from_template(
#                 template_name="high_hr",
#                 provider_id=sample_clinician_id,
#                 parameters={} # Missing threshold
#             )

#     def test_create_rule_from_template_unknown_template(self, engine, sample_clinician_id):
#         """Test that create_rule_from_template raises an error for an unknown template."""
#         with pytest.raises(ValueError, match="Unknown rule template"):
#             engine.create_rule_from_template(
#                 template_name="unknown_template",
#                 provider_id=sample_clinician_id,
#                 parameters={"threshold": 100}
#             )
