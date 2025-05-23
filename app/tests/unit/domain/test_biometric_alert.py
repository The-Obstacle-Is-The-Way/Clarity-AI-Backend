from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest

# Import status enum from domain entities instead of schemas
from app.domain.entities.biometric_alert import AlertStatusEnum as AlertStatus

# Import from biometric_event_processor
from app.domain.services.biometric_event_processor import AlertPriority, BiometricAlert


@pytest.fixture
def sample_patient_id() -> str:
    """Create a sample patient ID."""
    return str(uuid4())


@pytest.fixture
def sample_rule_id() -> str:
    """Create a sample rule ID."""
    return str(uuid4())


@pytest.fixture
def sample_alert_id() -> str:
    """Create a sample alert ID."""
    return str(uuid4())


@pytest.fixture
def sample_data_points() -> list[dict[str, Any]]:
    """Create sample biometric data points."""
    return [
        {
            "data_type": "heart_rate",
            "value": 120.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "apple_watch",
        }
    ]


@pytest.fixture
def sample_biometric_alert(
    sample_patient_id, sample_alert_id, sample_rule_id, sample_data_points
) -> BiometricAlert:
    """Create a sample biometric alert for testing."""
    now = datetime.now(timezone.utc)

    return BiometricAlert(
        patient_id=sample_patient_id,
        alert_id=sample_alert_id,
        alert_type="elevated_heart_rate",
        description="Heart rate exceeded threshold",
        priority=AlertPriority.WARNING,
        data_points=sample_data_points,
        rule_id=sample_rule_id,
        created_at=now,
        updated_at=now,
        status=AlertStatus.NEW,
    )


class TestBiometricAlert:
    """Tests for the BiometricAlert domain entity."""

    def test_biometric_alert_creation(
        self, sample_patient_id, sample_alert_id, sample_rule_id, sample_data_points
    ) -> None:
        """Test that a BiometricAlert can be properly created."""
        # Arrange
        now = datetime.now(timezone.utc)

        # Act
        alert = BiometricAlert(
            patient_id=sample_patient_id,
            alert_id=sample_alert_id,
            alert_type="elevated_heart_rate",
            description="Heart rate exceeded threshold",
            priority=AlertPriority.WARNING,
            data_points=sample_data_points,
            rule_id=sample_rule_id,
            created_at=now,
            updated_at=now,
            status=AlertStatus.NEW,
        )

        # Assert
        assert alert.patient_id == sample_patient_id
        assert alert.alert_id == sample_alert_id
        assert alert.alert_type == "elevated_heart_rate"
        assert alert.description == "Heart rate exceeded threshold"
        assert alert.priority == AlertPriority.WARNING
        assert alert.data_points == sample_data_points
        assert alert.rule_id == sample_rule_id
        assert alert.created_at == now
        assert alert.updated_at == now
        assert alert.status == AlertStatus.NEW

    def test_biometric_alert_acknowledged(self, sample_biometric_alert) -> None:
        """Test that a BiometricAlert can be acknowledged."""
        # Arrange
        provider_id = str(uuid4())
        ack_time = datetime.now(timezone.utc)

        # Act
        sample_biometric_alert.acknowledge(provider_id, ack_time)

        # Assert
        assert sample_biometric_alert.status == AlertStatus.ACKNOWLEDGED
        assert sample_biometric_alert.acknowledged_by == provider_id
        assert sample_biometric_alert.acknowledged_at == ack_time

    def test_biometric_alert_resolved(self, sample_biometric_alert) -> None:
        """Test that a BiometricAlert can be resolved."""
        # Arrange
        provider_id = str(uuid4())
        resolution_time = datetime.now(timezone.utc)
        resolution_note = "Issue addressed with patient"

        # Act
        sample_biometric_alert.resolve(provider_id, resolution_time, resolution_note)

        # Assert
        assert sample_biometric_alert.status == AlertStatus.RESOLVED
        assert sample_biometric_alert.resolved_by == provider_id
        assert sample_biometric_alert.resolved_at == resolution_time
        assert sample_biometric_alert.resolution_note == resolution_note
