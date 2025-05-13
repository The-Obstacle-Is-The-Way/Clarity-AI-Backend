"""
Migrated from standalone test: app/tests/standalone/core/test_standalone_biometric_processor.py

This test has been migrated to use the actual implementation
instead of a self-contained duplicate implementation.
"""

import unittest
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4
from unittest.mock import MagicMock, patch

import pytest

from app.domain.entities.biometric_twin import BiometricDataPoint
from app.domain.services.biometric_event_processor import (
    AlertRule,
    BiometricAlert,
    BiometricEventProcessor,
    AlertObserver,
    AlertPriority,
    AlertStatusEnum,
)

# Needed for tests that were using standalone implementations
class ComparisonOperator(str, Enum):
    """Comparison operators for rule conditions."""
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"

class AlertSeverity(str, Enum):
    """Severity levels for alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Test AlertRule class
class TestAlertRule(unittest.TestCase):
    """Test cases for AlertRule class."""

    def test_initialize(self):
        """Test initialization of AlertRule."""
        rule = AlertRule(
            rule_id="rule123",
            name="High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": "greater_than",
                "threshold": 100
            },
            created_by=uuid4(),
            patient_id=None,
            is_active=True
        )

        assert rule.name == "High Heart Rate"
        assert rule.condition.get("data_type") == "heart_rate"
        assert rule.condition.get("operator") == "greater_than"
        assert rule.condition.get("threshold") == 100
        assert rule.patient_id is None
        assert rule.priority == AlertPriority.WARNING
        assert rule.description == "Alert when heart rate exceeds 100 bpm"
        assert rule.is_active is True
        assert isinstance(rule.rule_id, str)

    def test_evaluate_greater_than(self):
        """Test evaluation with greater_than operator."""
        rule = AlertRule(
            rule_id="rule123",
            name="High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": "greater_than",
                "threshold": 100
            },
            created_by=uuid4()
        )

        # Value above threshold should trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=110,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is True

        # Value equal to threshold should not trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=100,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is False

        # Value below threshold should not trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=90,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is False

    def test_evaluate_greater_than_or_equal(self):
        """Test evaluation with greater_than_or_equal operator."""
        rule = AlertRule(
            rule_id="rule123",
            name="High Heart Rate",
            description="Alert when heart rate is at least 100 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": "greater_than_or_equal",
                "threshold": 100
            },
            created_by=uuid4()
        )

        # Value above threshold should trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=110,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is True

        # Value equal to threshold should trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=100,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is True

        # Value below threshold should not trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=90,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is False

    def test_evaluate_less_than(self):
        """Test evaluation with less_than operator."""
        rule = AlertRule(
            rule_id="rule123",
            name="Low Heart Rate",
            description="Alert when heart rate is below 60 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": "less_than",
                "threshold": 60
            },
            created_by=uuid4()
        )

        # Value above threshold should not trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=70,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is False

        # Value equal to threshold should not trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=60,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is False

        # Value below threshold should trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=50,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is True

    def test_evaluate_different_data_type(self):
        """Test evaluation with mismatched data type."""
        rule = AlertRule(
            rule_id="rule123",
            name="High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": "greater_than",
                "threshold": 100
            },
            created_by=uuid4()
        )

        # Different data type should not trigger
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="temperature",
            value=38.5,
            timestamp=datetime.now(),
            source="test"
        )
        assert rule.evaluate(data_point) is False

# Mock observer for testing
class MockAlertObserver(AlertObserver):
    """Mock observer for testing."""

    def __init__(self):
        """Initialize with tracking of notifications."""
        self.notifications = []

    def notify(self, alert: BiometricAlert):
        """Record notification."""
        self.notifications.append(alert)


# Test BiometricEventProcessor
class TestBiometricEventProcessor:
    """Test cases for BiometricEventProcessor."""

    def test_initialize(self):
        """Test initialization of processor."""
        processor = BiometricEventProcessor()
        # In the actual implementation, rules is a dict, not a list
        assert isinstance(processor.rules, dict)
        assert len(processor.rules) == 0
        # In the actual implementation, observers is a dict with priority keys
        assert isinstance(processor.observers, dict)
        # Check that each priority list is empty
        for priority_list in processor.observers.values():
            assert len(priority_list) == 0

    def test_add_rule(self):
        """Test adding rules to processor."""
        processor = BiometricEventProcessor()
        
        rule1 = AlertRule(
            rule_id="rule1",
            name="High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": "greater_than",
                "threshold": 100
            },
            created_by=uuid4()
        )
        
        rule2 = AlertRule(
            rule_id="rule2",
            name="Low Blood Oxygen",
            description="Alert when oxygen saturation is below 95%",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "oxygen_saturation",
                "operator": "less_than",
                "threshold": 95
            },
            created_by=uuid4()
        )
        
        processor.add_rule(rule1)
        processor.add_rule(rule2)
        
        assert len(processor.rules) == 2
        # Check that rules are stored in the dictionary by rule_id
        assert rule1.rule_id in processor.rules
        assert rule2.rule_id in processor.rules
        assert processor.rules[rule1.rule_id] == rule1
        assert processor.rules[rule2.rule_id] == rule2

    def test_register_observer(self):
        """Test registering observers."""
        processor = BiometricEventProcessor()
        observer = MockAlertObserver()
        
        processor.register_observer(observer)
        assert len(processor.observers) > 0
        # Check that observer is in one of the priority lists
        all_observers = set()
        for priority_list in processor.observers.values():
            all_observers.update(priority_list)
        assert observer in all_observers

    def test_unregister_observer(self):
        """Test unregistering observers."""
        processor = BiometricEventProcessor()
        observer = MockAlertObserver()
        
        processor.register_observer(observer)
        
        # Check that observer is registered
        all_observers = set()
        for priority_list in processor.observers.values():
            all_observers.update(priority_list)
        assert observer in all_observers
        
        processor.unregister_observer(observer)
        
        # Check that observer is unregistered
        all_observers = set()
        for priority_list in processor.observers.values():
            all_observers.update(priority_list)
        assert observer not in all_observers

    def test_process_data_point_no_alerts(self):
        """Test processing data point with no alerts triggered."""
        processor = BiometricEventProcessor()
        observer = MockAlertObserver()
        processor.register_observer(observer)
        
        rule = AlertRule(
            rule_id="rule1",
            name="High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": "greater_than",
                "threshold": 100
            },
            created_by=uuid4()
        )
        processor.add_rule(rule)
        
        # Data point below threshold
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=uuid4(),
            data_type="heart_rate",
            value=90,
            timestamp=datetime.now(),
            source="test"
        )
        
        alerts = processor.process_data_point(data_point)
        assert len(alerts) == 0
        assert len(observer.notifications) == 0

    def test_process_data_point_with_alert(self):
        """Test processing data point that triggers an alert."""
        processor = BiometricEventProcessor()
        observer = MockAlertObserver()
        processor.register_observer(observer)
        
        test_time = datetime(2023, 1, 1, 12, 0, 0)
        patient_id = uuid4()
        created_by = uuid4()
        
        rule = AlertRule(
            rule_id="rule1",
            name="High Heart Rate",
            description="Alert when heart rate exceeds 100 bpm",
            priority=AlertPriority.WARNING,
            condition={
                "data_type": "heart_rate",
                "operator": "greater_than",
                "threshold": 100
            },
            created_by=created_by
        )
        processor.add_rule(rule)
        
        # Data point above threshold
        data_point = BiometricDataPoint(
            data_id=uuid4(),
            patient_id=patient_id,
            data_type="heart_rate",
            value=110,
            timestamp=test_time,
            source="test"
        )
        
        alerts = processor.process_data_point(data_point)
        
        # Verify alert was created
        assert len(alerts) == 1
        assert alerts[0].patient_id == patient_id
        assert alerts[0].rule_id == rule.rule_id
        assert alerts[0].rule_name == "High Heart Rate"
        assert alerts[0].priority == AlertPriority.WARNING
        
        # Verify observer was notified
        assert len(observer.notifications) == 1
