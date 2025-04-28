"""
Unit tests for the BiometricEventProcessor.

These tests verify that the BiometricEventProcessor correctly processes
biometric data points, evaluates rules, and notifies observers.
"""

from datetime import datetime
from app.domain.utils.datetime_utils import UTC
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
    ClinicalRuleEngine,
    EmailAlertObserver,
    InAppAlertObserver,
    SMSAlertObserver
)



@pytest.fixture
def sample_patient_id():
    """
    Return a sample patient UUID for testing.
    """
    return UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def sample_clinician_id():
    """
    Return a sample clinician UUID for testing.
    """
    return UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def sample_data_point(sample_patient_id):
    """
    Return a sample biometric data point for testing.
    """
    return BiometricDataPoint(
        data_id=UUID("00000000-0000-0000-0000-000000000002"),
        patient_id=sample_patient_id,
        data_type="heart_rate",
        value=120.0,
        timestamp=datetime.now(UTC),
        source="apple_watch",
        metadata={"activity": "resting"},
        confidence=0.95
    )
    


@pytest.fixture
def sample_rule(sample_clinician_id):
    """
    Return a sample alert rule for testing.
    """
    return AlertRule(
        rule_id="test-rule-1",
        name="High Heart Rate",
        description="Alert when heart rate exceeds 100 bpm",
        priority=AlertPriority.WARNING,
        condition={
            "data_type": "heart_rate",
            "operator": ">",
            "threshold": 100.0
        },
        created_by=sample_clinician_id
    )
    


@pytest.fixture
def mock_observer():
    """
    Return a mock observer for testing.
    """
    observer = MagicMock(spec=AlertObserver)
    observer.notify = MagicMock()
    return observer


@pytest.fixture
def processor(mock_observer):
    """
    Return a BiometricEventProcessor with a mock observer for testing.
    """
    processor = BiometricEventProcessor()
    processor.register_observer(mock_observer)
    return processor


class TestAlertRule:
    """
    Tests for the AlertRule class.
    """

    @pytest.mark.standalone()
    def test_init_valid(self, sample_clinician_id):
        """
        Test initializing an AlertRule with valid parameters.
        """
        rule = AlertRule(
            rule_id="test-rule-1",
            name="High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": ">",
                "threshold": 100.0
            },
            created_by=sample_clinician_id
        )
        

        assert rule.rule_id == "test-rule-1"
        assert rule.name == "High Heart Rate"
        assert rule.description == "Alert when heart rate exceeds 100 bpm"
        assert rule.priority == AlertPriority.WARNING
        assert rule.condition["data_type"] == "heart_rate"
        assert rule.condition["operator"] == ">"
        assert rule.condition["threshold"] == 100.0
        assert rule.created_by == sample_clinician_id

    @pytest.mark.standalone()
    def test_init_invalid_condition(self, sample_clinician_id):
        """
        Test initializing an AlertRule with an invalid condition.
        """
        with pytest.raises(ValidationError):
            AlertRule(
                rule_id="test-rule-1",
                name="High Heart Rate",
                description="Alert when heart rate exceeds 100 bpm",
                priority=AlertPriority.WARNING,
                condition={
                    # Missing required fields
                    "data_type": "heart_rate"
                },
                created_by=sample_clinician_id
            )
            

    @pytest.mark.standalone()
    def test_evaluate_true(self, sample_data_point, sample_rule):
        """
        Test evaluating a rule that should return True.
        """
        # The sample data point has heart_rate=120, which is > 100
        result = sample_rule.evaluate(sample_data_point)
        assert result is True

    @pytest.mark.standalone()
    def test_evaluate_false(self, sample_data_point, sample_rule):
        """
        Test evaluating a rule that should return False.
        """
        # Modify the data point to have a heart rate below the threshold
        sample_data_point.value = 90.0
        result = sample_rule.evaluate(sample_data_point)
        assert result is False

    @pytest.mark.standalone()
    def test_evaluate_different_data_type(self, sample_data_point, sample_rule):
        """
        Test evaluating a rule with a different data type.
        """
        # Modify the data point to have a different data type
        sample_data_point.data_type = "blood_pressure"
        result = sample_rule.evaluate(sample_data_point)
        assert result is False


class TestBiometricEventProcessor:
    """
    Tests for the BiometricEventProcessor class.
    """

    @pytest.mark.standalone()
    def test_register_rule(self, processor, sample_rule):
        """
        Test registering a rule with the processor.
        """
        processor.register_rule(sample_rule)
        assert sample_rule.rule_id in processor.rules
        assert processor.rules[sample_rule.rule_id] == sample_rule

    @pytest.mark.standalone()
    def test_register_observer(self, processor):
        """
        Test registering an observer with the processor.
        """
        observer = MagicMock(spec=AlertObserver)
        processor.register_observer(observer)
        assert observer in processor.observers

    @pytest.mark.standalone()
    def test_process_data_point_no_alert(self, processor, sample_data_point, sample_rule):
        """
        Test processing a data point that doesn't trigger an alert.
        """
        # Modify the data point to have a heart rate below the threshold
        sample_data_point.value = 90.0
        processor.register_rule(sample_rule)
        
        # Process the data point
        processor.process_data_point(sample_data_point)
        
        # Verify no alerts were generated
        assert len(processor.alerts) == 0
        # Verify no observers were notified
        for observer in processor.observers:
            observer.notify.assert_not_called()

    @pytest.mark.standalone()
    def test_process_data_point_with_alert(self, processor, sample_data_point, sample_rule, mock_observer):
        """
        Test processing a data point that triggers an alert.
        """
        processor.register_rule(sample_rule)
        
        # Process the data point (value=120, which is > 100)
        processor.process_data_point(sample_data_point)
        
        # Verify an alert was generated
        assert len(processor.alerts) == 1
        alert = processor.alerts[0]
        assert alert.rule_id == sample_rule.rule_id
        assert alert.patient_id == sample_data_point.patient_id
        assert alert.data_point == sample_data_point
        assert alert.priority == sample_rule.priority
        
        # Verify the observer was notified
        mock_observer.notify.assert_called_once()
        assert mock_observer.notify.call_args[0][0] == alert


class TestAlertObservers:
    """
    Tests for the various AlertObserver implementations.
    """

    @pytest.mark.standalone()
    def test_in_app_observer(self, sample_data_point, sample_rule):
        """
        Test the InAppAlertObserver.
        """
        observer = InAppAlertObserver()
        alert = BiometricAlert(
            alert_id=UUID("00000000-0000-0000-0000-000000000003"),
            rule_id=sample_rule.rule_id,
            patient_id=sample_data_point.patient_id,
            data_point=sample_data_point,
            timestamp=datetime.now(UTC),
            priority=sample_rule.priority
        )
        
        
        # Mock the send_in_app_notification method
        with patch.object(observer, 'send_in_app_notification') as mock_send:
            observer.notify(alert)
            mock_send.assert_called_once_with(alert)

    @pytest.mark.standalone()
    def test_email_observer(self, sample_data_point, sample_rule):
        """
        Test the EmailAlertObserver.
        """
        observer = EmailAlertObserver()
        alert = BiometricAlert(
            alert_id=UUID("00000000-0000-0000-0000-000000000003"),
            rule_id=sample_rule.rule_id,
            patient_id=sample_data_point.patient_id,
            data_point=sample_data_point,
            timestamp=datetime.now(UTC),
            priority=sample_rule.priority
        )
        
        
        # Mock the send_email method
        with patch.object(observer, 'send_email') as mock_send:
            observer.notify(alert)
            # Only high priority alerts should trigger an email
            if alert.priority == AlertPriority.HIGH:
                mock_send.assert_called_once_with(alert)
            else:
                mock_send.assert_not_called()

    @pytest.mark.standalone()
    def test_sms_observer(self, sample_data_point, sample_rule):
        """
        Test the SMSAlertObserver.
        """
        observer = SMSAlertObserver()
        alert = BiometricAlert(
            alert_id=UUID("00000000-0000-0000-0000-000000000003"),
            rule_id=sample_rule.rule_id,
            patient_id=sample_data_point.patient_id,
            data_point=sample_data_point,
            timestamp=datetime.now(UTC),
            priority=sample_rule.priority
        )
        
        
        # Mock the send_sms method
        with patch.object(observer, 'send_sms') as mock_send:
            observer.notify(alert)
            # Only critical priority alerts should trigger an SMS
            if alert.priority == AlertPriority.CRITICAL:
                mock_send.assert_called_once_with(alert)
            else:
                mock_send.assert_not_called()


class TestClinicalRuleEngine:
    """
    Tests for the ClinicalRuleEngine class.
    """

    @pytest.mark.standalone()
    def test_register_rule_template(self):
        """
        Test registering a rule template.
        """
        engine = ClinicalRuleEngine()
        template_id = "high-heart-rate"
        template = {
            "name": "High Heart Rate",
            "description": "Alert when heart rate exceeds threshold",
            "priority": AlertPriority.WARNING,
            "condition": {
                "data_type": "heart_rate",
                "operator": ">",
                "threshold": "${threshold}"
            },
            "default_threshold": 100.0
        }
        
        engine.register_rule_template(template, template_id)
        assert template_id in engine.rule_templates
        assert engine.rule_templates[template_id] == template

    @pytest.mark.standalone()
    def test_create_rule_from_template(self, sample_clinician_id):
        """
        Test creating a rule from a template.
        """
        engine = ClinicalRuleEngine()
        template_id = "high-heart-rate"
        template = {
            "name": "High Heart Rate",
            "description": "Alert when heart rate exceeds threshold",
            "priority": AlertPriority.WARNING,
            "condition": {
                "data_type": "heart_rate",
                "operator": ">",
                "threshold": "${threshold}"
            },
            "default_threshold": 100.0
        }

        engine.register_rule_template(template, template_id)

        # Create a rule from the template
        parameters = {"threshold": 120.0}
        rule_id = "custom-heart-rate-rule"
        rule = engine.create_rule_from_template(
            template_id=template_id,
            rule_id=rule_id,
            parameters=parameters,
            created_by=sample_clinician_id
        )
        
        # Verify the rule was created correctly
        assert rule.name == template["name"]
        assert rule.description == template["description"]
        assert rule.priority == template["priority"]
        assert rule.condition["data_type"] == template["condition"]["data_type"]
        assert rule.condition["operator"] == template["condition"]["operator"]
        assert rule.condition["threshold"] == parameters["threshold"]  # Overridden
        assert rule.created_by == sample_clinician_id

    @pytest.mark.standalone()
    def test_create_rule_from_nonexistent_template(self, sample_clinician_id):
        """
        Test creating a rule from a nonexistent template.
        """
        engine = ClinicalRuleEngine()
        # The implementation actually raises ValueError, not ValidationError
        with pytest.raises(ValueError):
            engine.create_rule_from_template(
                template_id="nonexistent",
                rule_id="test-nonexistent-rule",
                parameters={},
                created_by=sample_clinician_id
            )
            