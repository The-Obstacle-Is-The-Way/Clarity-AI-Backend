# -*- coding: utf-8 -*-
"""
Unit tests for the BiometricAlertAuditService.

These tests verify that the BiometricAlertAuditService correctly
maintains an audit trail for biometric alerts.
"""

import pytest
from datetime import datetime
from app.domain.utils.datetime_utils import UTC, now_utc
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

# Corrected import path for BiometricAlert and AlertPriority
from app.domain.services.biometric_event_processor import AlertPriority, BiometricAlert
from app.domain.interfaces.alert_observer import AlertObserver
from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.services.biometric_alert_audit_service import BiometricAlertAuditService


@pytest.mark.db_required()
class TestBiometricAlertAuditService:
    """Tests for the BiometricAlertAuditService."""

    @pytest.fixture
    def mock_alert_repository(self):
        """Create a mock BiometricAlertRepository."""
        repo = AsyncMock(spec=BiometricAlertRepository)
        repo.get_by_id = AsyncMock()
        repo.update_status = AsyncMock()
        return repo

    @pytest.fixture
    def mock_audit_logger(self):
        """Create a mock audit logger."""
        logger = AsyncMock()
        logger.log_event = AsyncMock()
        logger.search_events = AsyncMock()
        return logger

    @pytest.fixture
    def audit_service(self, mock_alert_repository, mock_audit_logger):
        """Create a BiometricAlertAuditService with mock dependencies."""
        return BiometricAlertAuditService(
            alert_repository=mock_alert_repository,
            audit_logger=mock_audit_logger
        )

    @pytest.fixture
    def sample_patient_id(self):
        """Create a sample patient ID."""
        return UUID('12345678-1234-5678-1234-567812345678')

    @pytest.fixture
    def sample_provider_id(self):
        """Create a sample provider ID."""
        return UUID('87654321-8765-4321-8765-432187654321')

    @pytest.fixture
    def sample_rule_id(self):
        """Create a sample rule ID."""
        return "rule-001"

    @pytest.fixture
    def sample_rule_name(self):
        return "Sample Rule Name"

    @pytest.fixture
    def sample_alert_id(self):
        """Create a sample alert ID."""
        return "alert-" + str(uuid4())

    @pytest.fixture
    def sample_data_point(self, sample_patient_id):
        """Mock data point as BiometricAlert requires it."""
        dp = MagicMock()
        dp.data_type = "heart_rate"
        dp.value = 130.0
        dp.timestamp = datetime.now(UTC)
        dp.source = "smartwatch"
        return dp

    @pytest.fixture
    def sample_alert(
        self,
        sample_patient_id: UUID,
        sample_rule_id: str,
        sample_rule_name: str,
        sample_alert_id: str,
        sample_data_point: MagicMock
    ) -> BiometricAlert:
        """Create a sample BiometricAlert using the correct constructor."""
        return BiometricAlert(
            alert_id=sample_alert_id,
            patient_id=sample_patient_id,
            rule_id=sample_rule_id,
            rule_name=sample_rule_name,
            priority=AlertPriority.URGENT,
            data_point=sample_data_point,
            message="Heart rate is significantly elevated",
            context={}
        )


    async def test_notify_alert_creates_audit_record(
        self, audit_service, mock_audit_logger, sample_alert
    ):
        """Test that notify_alert creates an audit record for a new alert."""
        # Execute
        await audit_service.notify_alert(sample_alert)

        # Verify
        mock_audit_logger.log_event.assert_called_once()
        log_args = mock_audit_logger.log_event.call_args.kwargs

        assert log_args["event_type"] == "alert_generated"
        assert log_args["resource_type"] == "biometric_alert"
        assert log_args["resource_id"] == str(sample_alert.alert_id)
        assert log_args["patient_id"] == str(sample_alert.patient_id)
        assert "alert" in log_args["data"]

        # Verify PHI sanitization and correct status field
        alert_data = log_args["data"]["alert"]
        assert "alert_id" in alert_data
        assert "rule_id" in alert_data
        assert "rule_name" in alert_data
        assert "priority" in alert_data
        assert "acknowledged" in alert_data
        assert alert_data["acknowledged"] is False
        assert "status" not in alert_data
        assert "created_at" in alert_data
        assert "data_points" not in alert_data
        assert "data_point" not in alert_data

    async def test_record_alert_acknowledgment(
        self, audit_service, mock_alert_repository, mock_audit_logger,
        sample_alert, sample_alert_id, sample_provider_id
    ):
        """Test that record_alert_acknowledgment logs the event correctly."""
        # Setup: The service now fetches the alert for context
        # Simulate the alert exists and is *already* acknowledged in the object passed
        # because the service *only logs* the event after the object state change.
        sample_alert.acknowledge(sample_provider_id)
        mock_alert_repository.get_by_id.return_value = sample_alert

        # Execute
        await audit_service.record_alert_acknowledgment(
            alert_id=sample_alert_id,
            provider_id=sample_provider_id,
            notes="Acknowledged by Dr. Smith"
        )

        # Verify
        mock_alert_repository.get_by_id.assert_called_once_with(sample_alert_id)
        mock_alert_repository.update_status.assert_not_called()

        mock_audit_logger.log_event.assert_called_once()
        log_args = mock_audit_logger.log_event.call_args.kwargs

        assert log_args["event_type"] == "alert_acknowledged"
        assert log_args["resource_type"] == "biometric_alert"
        assert log_args["resource_id"] == str(sample_alert_id)
        assert log_args["actor_id"] == str(sample_provider_id)
        assert log_args["patient_id"] == str(sample_alert.patient_id)
        assert log_args["notes"] == "Acknowledged by Dr. Smith"
        assert log_args["data"]["alert"]["acknowledged"] is True
        assert log_args["data"]["alert"]["acknowledged_by"] == str(sample_provider_id)
        assert log_args["data"]["alert"]["acknowledged_at"] is not None

    async def test_create_alert_audit_record_sanitizes_phi(
        self, audit_service, mock_audit_logger, sample_alert, sample_provider_id
    ):
        """Test that _create_alert_audit_record properly sanitizes PHI and uses correct fields."""
        # Execute
        await audit_service._create_alert_audit_record(
            alert=sample_alert,
            event_type="test_event",
            event_description="Test event description",
            actor_id=sample_provider_id,
            notes="Test notes",
            additional_data={"additional": "data"}
        )

        # Verify
        mock_audit_logger.log_event.assert_called_once()
        log_args = mock_audit_logger.log_event.call_args.kwargs

        assert log_args["event_type"] == "test_event"
        assert log_args["event_description"] == "Test event description"
        assert log_args["resource_type"] == "biometric_alert"
        assert log_args["resource_id"] == str(sample_alert.alert_id)
        assert log_args["actor_id"] == str(sample_provider_id)
        assert log_args["patient_id"] == str(sample_alert.patient_id)
        assert log_args["notes"] == "Test notes"

        # Verify sanitized alert data
        alert_data = log_args["data"]["alert"]
        assert "alert_id" in alert_data
        assert "rule_id" in alert_data
        assert "rule_name" in alert_data
        assert "priority" in alert_data
        assert "acknowledged" in alert_data
        assert "status" not in alert_data

        # Ensure no PHI is included
        assert "data_points" not in alert_data
        assert "data_point" not in alert_data
        assert "message" not in alert_data
        assert "context" not in alert_data

        # Verify additional data is included
        assert log_args["data"]["additional"] == "data"

    async def test_search_audit_trail(
        self, audit_service, mock_audit_logger, sample_patient_id,
        sample_alert_id, sample_provider_id
    ):
        """Test that search_audit_trail correctly builds search criteria."""
        # Setup
        mock_audit_logger.search_events.return_value = []
        start_date = datetime.now(UTC)
        end_date = datetime.now(UTC)

        # Execute
        await audit_service.search_audit_trail(
            patient_id=sample_patient_id,
            alert_id=sample_alert_id,
            provider_id=sample_provider_id,
            event_type="alert_resolved",
            start_date=start_date,
            end_date=end_date,
            limit=50,
            offset=10
        )

        # Verify
        assert mock_audit_logger.search_events.call_count == 1
        search_args = mock_audit_logger.search_events.call_args[1]

        criteria = search_args["criteria"]
        assert criteria["patient_id"] == str(sample_patient_id)
        assert criteria["resource_id"] == str(sample_alert_id)
        assert criteria["resource_type"] == "biometric_alert"
        assert criteria["actor_id"] == str(sample_provider_id)
        assert criteria["event_type"] == "alert_resolved"
        assert criteria["start_date"] == start_date
        assert criteria["end_date"] == end_date

        assert search_args["limit"] == 50
        assert search_args["offset"] == 10

    async def test_no_audit_record_for_nonexistent_alert_acknowledgment(
        self, audit_service, mock_alert_repository, mock_audit_logger,
        sample_alert_id, sample_provider_id
    ):
        """Test that no audit record is created when acknowledging a nonexistent alert."""
        # Setup
        mock_alert_repository.get_by_id.return_value = None

        # Execute
        await audit_service.record_alert_acknowledgment(
            alert_id=sample_alert_id,
            provider_id=sample_provider_id,
            notes="Acknowledged by Dr. Smith"
        )

        # Verify
        mock_alert_repository.get_by_id.assert_called_once_with(sample_alert_id)
        mock_alert_repository.update_status.assert_not_called()
        mock_audit_logger.log_event.assert_not_called()
