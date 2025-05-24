"""
Unit tests for the BiometricAlertNotificationService.

These tests verify that the BiometricAlertNotificationService correctly
sends HIPAA-compliant notifications when biometric alerts are generated.
"""

from datetime import datetime
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

# Correct interface import
# Correct repository import
from app.domain.services.biometric_alert_notification_service import (
    BiometricAlertNotificationService,
    NotificationChannel,
)

# Corrected import path for BiometricAlert and AlertPriority
from app.domain.services.biometric_event_processor import AlertPriority, BiometricAlert
from app.domain.utils.datetime_utils import UTC


@pytest.mark.db_required()
class TestBiometricAlertNotificationService:
    """Tests for the BiometricAlertNotificationService."""

    @pytest.fixture
    def mock_alert_repository(self):
        """Create a mock BiometricAlertRepository."""
        repo = AsyncMock()
        repo.save = AsyncMock()
        return repo

    @pytest.fixture
    def mock_notification_service(self):
        """Create a mock notification service provider."""
        service = AsyncMock()
        service.send_sms = AsyncMock()
        service.send_email = AsyncMock()
        service.send_in_app_notification = AsyncMock()
        service.send_push_notification = AsyncMock()
        return service

    @pytest.fixture
    def notification_service(self, mock_alert_repository, mock_notification_service):
        """Create a BiometricAlertNotificationService with mock dependencies."""
        return BiometricAlertNotificationService(mock_alert_repository, mock_notification_service)

    @pytest.fixture
    def sample_patient_id(self):
        """Create a sample patient ID."""
        return UUID("12345678-1234-5678-1234-567812345678")

    @pytest.fixture
    def sample_provider_id(self):
        """Create a sample provider ID."""
        return UUID("87654321-8765-4321-8765-432187654321")

    @pytest.fixture
    def sample_rule_id(self):
        """Create a sample rule ID."""
        return UUID("11111111-2222-3333-4444-555555555555")

    @pytest.fixture
    def sample_urgent_alert(self, sample_patient_id, sample_rule_id):
        """Create a sample urgent BiometricAlert."""
        return BiometricAlert(
            patient_id=sample_patient_id,
            alert_type="elevated_heart_rate",
            description="Heart rate is significantly elevated",
            priority=AlertPriority.URGENT,
            data_points=[
                {
                    "data_type": "heart_rate",
                    "value": 130,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "source": "smartwatch",
                }
            ],
            rule_id=sample_rule_id,
        )

    @pytest.fixture
    def sample_warning_alert(self, sample_patient_id, sample_rule_id):
        """Create a sample warning BiometricAlert."""
        return BiometricAlert(
            patient_id=sample_patient_id,
            alert_type="sleep_disruption",
            description="Sleep quality is poor",
            priority=AlertPriority.WARNING,
            data_points=[
                {
                    "data_type": "sleep_quality",
                    "value": 30,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "source": "sleep_tracker",
                }
            ],
            rule_id=sample_rule_id,
        )

    @pytest.fixture
    def sample_info_alert(self, sample_patient_id, sample_rule_id):
        """Create a sample informational BiometricAlert."""
        return BiometricAlert(
            patient_id=sample_patient_id,
            alert_type="low_activity",
            description="Physical activity is below target",
            priority=AlertPriority.INFORMATIONAL,
            data_points=[
                {
                    "data_type": "step_count",
                    "value": 2000,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "source": "fitness_tracker",
                }
            ],
            rule_id=sample_rule_id,
        )

    @pytest.mark.asyncio
    async def test_notify_alert_urgent_priority(
        self, notification_service, mock_notification_service, sample_urgent_alert
    ) -> None:
        """Test that notify_alert sends notifications through all channels for urgent alerts."""
        # Execute
        await notification_service.notify_alert(sample_urgent_alert)

        # Verify
        assert mock_notification_service.send_sms.call_count == 1
        assert mock_notification_service.send_email.call_count == 1
        assert mock_notification_service.send_in_app_notification.call_count == 1
        assert mock_notification_service.send_push_notification.call_count == 1

        # Verify SMS content is HIPAA-compliant (Moved inside test)
        sms_message = mock_notification_service.send_sms.call_args[0][1]
        assert "SECURE" in sms_message
        assert "URGENT" in sms_message
        # Ensure no PHI is included
        assert sample_urgent_alert.patient_id.hex not in sms_message

    @pytest.mark.asyncio
    async def test_notify_alert_warning_priority(
        self, notification_service, mock_notification_service, sample_warning_alert
    ) -> None:
        """Test that notify_alert sends notifications through appropriate channels for warning alerts."""
        # Execute
        await notification_service.notify_alert(sample_warning_alert)

        # Verify
        assert mock_notification_service.send_sms.call_count == 0  # SMS not used for warnings
        assert mock_notification_service.send_email.call_count == 1
        assert mock_notification_service.send_in_app_notification.call_count == 1
        assert mock_notification_service.send_push_notification.call_count == 1

    @pytest.mark.asyncio
    async def test_notify_alert_info_priority(
        self, notification_service, mock_notification_service, sample_info_alert
    ) -> None:
        """Test that notify_alert sends notifications through in-app only for informational alerts."""
        # Execute
        await notification_service.notify_alert(sample_info_alert)

        # Verify
        assert mock_notification_service.send_sms.call_count == 0
        assert mock_notification_service.send_email.call_count == 0
        assert mock_notification_service.send_in_app_notification.call_count == 1
        assert mock_notification_service.send_push_notification.call_count == 0

    @pytest.mark.asyncio
    async def test_hipaa_compliant_message_creation(
        self, notification_service, sample_urgent_alert
    ) -> None:
        """Test that HIPAA-compliant messages are created correctly."""
        # Execute
        sms_message = notification_service._create_hipaa_compliant_message(
            sample_urgent_alert, NotificationChannel.SMS
        )
        email_message = notification_service._create_hipaa_compliant_message(
            sample_urgent_alert, NotificationChannel.EMAIL
        )

        # Verify SMS message
        assert "SECURE" in sms_message
        assert "URGENT" in sms_message
        assert "log in to the secure portal" in sms_message

        # Verify email message
        assert "SECURE" in email_message
        assert "URGENT" in email_message
        assert "Alert Type" in email_message
        assert "Time" in email_message
        assert "log in to the secure portal" in email_message

        # Ensure no PHI is included in either message
        patient_id_str = str(sample_urgent_alert.patient_id)
        assert patient_id_str not in sms_message
        assert patient_id_str not in email_message

    @pytest.mark.asyncio
    async def test_get_channels_for_priority(self, notification_service) -> None:
        """Test that appropriate channels are selected based on alert priority."""
        # Execute
        urgent_channels = notification_service._get_channels_for_priority(AlertPriority.URGENT)
        warning_channels = notification_service._get_channels_for_priority(AlertPriority.WARNING)
        info_channels = notification_service._get_channels_for_priority(AlertPriority.INFORMATIONAL)

        # Verify
        assert len(urgent_channels) == 4
        assert NotificationChannel.SMS in urgent_channels
        assert NotificationChannel.EMAIL in urgent_channels
        assert NotificationChannel.IN_APP in urgent_channels
        assert NotificationChannel.PUSH in urgent_channels

        assert len(warning_channels) == 3
        assert NotificationChannel.SMS not in warning_channels
        assert NotificationChannel.EMAIL in warning_channels
        assert NotificationChannel.IN_APP in warning_channels
        assert NotificationChannel.PUSH in warning_channels

        assert len(info_channels) == 1
        assert info_channels[0] == NotificationChannel.IN_APP

    @pytest.mark.asyncio
    async def test_get_alert_recipients(self, notification_service, sample_urgent_alert) -> None:
        """Test that alert recipients are correctly determined."""
        # Execute
        recipients = await notification_service._get_alert_recipients(sample_urgent_alert)

        # Verify
        assert len(recipients) == 1
        assert "provider_id" in recipients[0]
        assert "name" in recipients[0]
        assert "email" in recipients[0]
        assert "phone" in recipients[0]
        assert "notification_preferences" in recipients[0]

    @pytest.mark.asyncio
    async def test_send_notification_filters_recipients(
        self, notification_service, mock_notification_service, sample_urgent_alert
    ) -> None:
        """Test that send_notification filters recipients based on their preferences."""
        # Setup
        recipients = [
            {
                "provider_id": "00000000-0000-0000-0000-000000000001",
                "name": "Provider 1",
                "email": "provider1@example.com",
                "phone": "+15555555551",
                "notification_preferences": {
                    "sms": True,
                    "email": True,
                    "in_app": True,
                    "push": True,
                },
            },
            {
                "provider_id": "00000000-0000-0000-0000-000000000002",
                "name": "Provider 2",
                "email": "provider2@example.com",
                "phone": "+15555555552",
                "notification_preferences": {
                    "sms": False,  # This provider doesn't want SMS
                    "email": True,
                    "in_app": True,
                    "push": True,
                },
            },
        ]

        # Execute - SMS channel should only notify Provider 1
        await notification_service._send_notification(
            sample_urgent_alert, NotificationChannel.SMS, recipients
        )

        # Verify
        assert mock_notification_service.send_sms.call_count == 1
        assert mock_notification_service.send_sms.call_args[0][0] == "+15555555551"

        # Reset mock
        mock_notification_service.send_sms.reset_mock()

        # Execute - Email channel should notify both providers
        await notification_service._send_notification(
            sample_urgent_alert, NotificationChannel.EMAIL, recipients
        )

        # Verify
        assert mock_notification_service.send_email.call_count == 2
