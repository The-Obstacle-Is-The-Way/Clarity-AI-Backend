"""
Tests for the AuditLogger class.

This module contains unit tests for the HIPAA-compliant audit logging functionality.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, ANY

import pytest

from app.infrastructure.security.audit.audit import AuditLogger


class TestAuditLogger:
    """Test suite for the AuditLogger class."""

    @pytest.fixture
    def mock_settings(self):
        """Fixture to create mock settings for testing."""
        with patch(
            "app.infrastructure.security.audit.audit.get_settings"
        ) as mock_get_settings:
            settings = MagicMock()
            settings.LOG_LEVEL = "INFO"
            settings.AUDIT_LOG_FILE = "logs/test_audit.log"
            settings.EXTERNAL_AUDIT_ENABLED = False
            mock_get_settings.return_value = settings
            yield mock_get_settings

    @pytest.fixture
    def mock_logger(self):
        """Fixture to create a mock logger for testing."""
        with patch(
            "app.infrastructure.security.audit.audit.logging.getLogger"
        ) as mock_get_logger:
            logger = MagicMock()
            mock_get_logger.return_value = logger
            yield logger

    @pytest.fixture
    def audit_logger(self, mock_settings, mock_logger):
        """Fixture to create an AuditLogger instance for testing."""
        # Create a directory for the log file
        os.makedirs("logs", exist_ok=True)

        # Create the audit logger
        logger = AuditLogger()

        # Clean up after the test
        yield logger

    def test_init(self, mock_settings, mock_logger):
        """Test initialization of the AuditLogger."""
        # Exercise
        logger = AuditLogger()

        # Verify
        assert logger.settings == mock_settings.return_value
        assert logger.log_level == logging.INFO
        assert logger.audit_log_file == "logs/test_audit.log"
        assert logger.external_audit_enabled is False
        assert logger.logger == mock_logger

    def test_log_phi_access(self, audit_logger, mock_logger):
        """Test logging of PHI access events."""
        # Setup
        user_id = str(uuid.uuid4())
        action = "view"
        resource_type = "patient"
        resource_id = str(uuid.uuid4())
        details = {"reason": "patient care"}

        # Exercise
        audit_logger.log_phi_access(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
        )

        # Verify
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "PHI_ACCESS" in call_args

        # Parse the JSON from the log message
        log_message = call_args.replace("PHI_ACCESS: ", "")
        log_data = json.loads(log_message)

        assert log_data["event_type"] == "phi_access"
        assert log_data["user_id"] == user_id
        assert log_data["action"] == action
        assert log_data["resource_type"] == resource_type
        assert log_data["resource_id"] == resource_id
        assert log_data["details"] == details

    def test_log_auth_event(self, audit_logger, mock_logger):
        """Test logging of authentication events."""
        # Setup
        event_type = "login"
        user_id = str(uuid.uuid4())
        success = True
        details = {"ip_address": "127.0.0.1"}

        # Exercise
        audit_logger.log_auth_event(
            event_type=event_type, user_id=user_id, success=success, details=details
        )

        # Verify
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "AUTH_EVENT" in call_args

        # Parse the JSON from the log message
        log_message = call_args.replace("AUTH_EVENT: ", "")
        log_data = json.loads(log_message)

        assert log_data["event_type"] == "auth_event"
        assert log_data["auth_type"] == event_type
        assert log_data["user_id"] == user_id
        assert log_data["success"] is success
        assert log_data["details"] == details

    def test_log_system_event(self, audit_logger, mock_logger):
        """Test logging of system events."""
        # Setup
        event_type = "startup"
        description = "System started successfully"
        details = {"version": "1.0.0"}
        user_id = str(uuid.uuid4())

        # Exercise
        audit_logger.log_system_event(
            event_type=event_type,
            description=description,
            details=details,
            user_id=user_id,
        )

        # Verify
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "SYSTEM_EVENT" in call_args

        # Parse the JSON from the log message
        log_message = call_args.replace("SYSTEM_EVENT: ", "")
        log_data = json.loads(log_message)

        assert log_data["event_type"] == "system_event"
        assert log_data["system_event_type"] == event_type
        assert log_data["description"] == description
        assert log_data["user_id"] == user_id
        assert log_data["details"] == details

    @patch(
        "app.infrastructure.security.audit.audit.AuditLogger._send_to_external_audit_service"
    )
    def test_external_audit_service_called(self, mock_send, mock_settings, mock_logger):
        """Test that external audit service is called when enabled."""
        # Setup
        mock_settings.return_value.EXTERNAL_AUDIT_ENABLED = True
        logger = AuditLogger()

        # Exercise
        logger.log_phi_access(
            user_id=str(uuid.uuid4()),
            action="view",
            resource_type="patient",
            resource_id=str(uuid.uuid4()),
            details={},
        )

        # Verify
        mock_send.assert_called_once()
        assert "event_id" in mock_send.call_args[0][0]
        assert "timestamp" in mock_send.call_args[0][0]
        assert "event_type" in mock_send.call_args[0][0]

    def test_file_handler_creation(self, mock_settings):
        """Test that file handler is created when audit log file is set."""
        # Setup
        with patch(
            "app.infrastructure.security.audit.audit.logging.FileHandler"
        ) as mock_file_handler:
            mock_file_handler.return_value = MagicMock()

            # Exercise
            logger = AuditLogger()

            # Verify
            mock_file_handler.assert_called_once_with("logs/test_audit.log")

    def test_directory_creation(self, mock_settings):
        """Test that log directory is created if it doesn't exist."""
        # Setup
        test_dir = "test_logs"
        mock_settings.return_value.AUDIT_LOG_FILE = f"{test_dir}/audit.log"

        # Remove the directory if it exists
        import shutil

        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)

        # Exercise
        logger = AuditLogger()

        # Verify
        assert os.path.exists(test_dir)

        # Clean up
        shutil.rmtree(test_dir)
