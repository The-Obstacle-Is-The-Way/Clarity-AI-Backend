"""
HIPAA Security Test Suite - Audit Logging Tests

Tests for the audit logging decorators and utilities to ensure HIPAA-compliant
audit trails are properly created and maintained.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from app.infrastructure.logging.audit import (
    audit_async_phi_access,
    audit_phi_access,
    clear_current_user,
    get_current_access_reason,
    get_current_user_id,
    set_current_user,
)


class TestAuditDecorators:
    """Test suite for audit logging decorators."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        # Clear any user context that might be set
        clear_current_user()

    def teardown_method(self):
        """Clean up after each test method."""
        # Clean up user context
        clear_current_user()

    def test_user_context_functions(self):
        """Test the user context management functions."""
        # Initially should be None
        assert get_current_user_id() is None
        assert get_current_access_reason() is None

        # Set user context
        set_current_user("test_user", "treatment")

        # Check values
        assert get_current_user_id() == "test_user"
        assert get_current_access_reason() == "treatment"

        # Clear context
        clear_current_user()

        # Should be None again
        assert get_current_user_id() is None
        assert get_current_access_reason() is None

    def test_audit_phi_access_decorator(self):
        """Test the audit_phi_access decorator."""
        # Mock the audit logger
        with patch(
            "app.infrastructure.logging.audit.get_audit_logger"
        ) as mock_get_logger:
            mock_audit_logger = MagicMock()
            mock_get_logger.return_value = mock_audit_logger

            # Define a test function with the decorator
            @audit_phi_access(
                resource_type="patient", action="view", phi_fields=["name", "dob"]
            )
            def get_patient_data(patient_id, *args, **kwargs):
                return {"id": patient_id, "name": "Test Patient", "dob": "1980-01-01"}

            # Set user context
            set_current_user("doctor_smith", "treatment")

            # Call the decorated function
            result = get_patient_data("patient123")

            # Verify the function worked
            assert result["id"] == "patient123"

            # Verify audit logs
            assert mock_audit_logger.log_data_modification.call_count == 2

            # Check first call (initiated)
            init_call_args = mock_audit_logger.log_data_modification.call_args_list[0][
                1
            ]
            assert init_call_args["user_id"] == "doctor_smith"
            assert init_call_args["action"] == "view"
            assert init_call_args["entity_type"] == "patient"
            assert init_call_args["entity_id"] == "patient123"
            assert init_call_args["status"] == "initiated"
            assert init_call_args["phi_fields"] == ["name", "dob"]

            # Check second call (success)
            success_call_args = mock_audit_logger.log_data_modification.call_args_list[
                1
            ][1]
            assert success_call_args["user_id"] == "doctor_smith"
            assert success_call_args["status"] == "success"

    def test_audit_phi_access_with_exception(self):
        """Test the audit_phi_access decorator when the function raises an exception."""
        # Mock the audit logger
        with patch(
            "app.infrastructure.logging.audit.get_audit_logger"
        ) as mock_get_logger:
            mock_audit_logger = MagicMock()
            mock_get_logger.return_value = mock_audit_logger

            # Define a test function with the decorator that raises an exception
            @audit_phi_access(resource_type="patient", action="view")
            def get_patient_data_with_error(patient_id):
                raise ValueError("Test error")

            # Set user context
            set_current_user("doctor_smith", "treatment")

            # Call the decorated function and expect an exception
            with pytest.raises(ValueError, match="Test error"):
                get_patient_data_with_error("patient123")

            # Verify audit logs
            assert mock_audit_logger.log_data_modification.call_count == 2

            # Check first call (initiated)
            init_call_args = mock_audit_logger.log_data_modification.call_args_list[0][
                1
            ]
            assert init_call_args["status"] == "initiated"

            # Check second call (failed)
            failed_call_args = mock_audit_logger.log_data_modification.call_args_list[
                1
            ][1]
            assert failed_call_args["status"] == "failed"
            assert "Test error" in failed_call_args["details"]

    def test_audit_phi_access_without_user_context(self):
        """Test the audit_phi_access decorator when no user context is set."""
        # Mock the audit logger
        with patch(
            "app.infrastructure.logging.audit.get_audit_logger"
        ) as mock_get_logger:
            mock_audit_logger = MagicMock()
            mock_get_logger.return_value = mock_audit_logger

            # Define a test function with the decorator
            @audit_phi_access(
                resource_type="patient",
                action="view",
                default_reason="system_operation",
            )
            def get_patient_data(patient_id):
                return {"id": patient_id, "name": "Test Patient"}

            # Call the decorated function without setting user context
            result = get_patient_data("patient123")

            # Verify the function worked
            assert result["id"] == "patient123"

            # Verify audit logs - should use "anonymous" for user_id
            assert mock_audit_logger.log_data_modification.call_count == 2

            # Check first call
            init_call_args = mock_audit_logger.log_data_modification.call_args_list[0][
                1
            ]
            assert init_call_args["user_id"] == "anonymous"
            assert init_call_args["action"] == "view"
            assert "system_operation" in init_call_args["details"]

    @pytest.mark.asyncio
    async def test_audit_async_phi_access_decorator(self):
        """Test the audit_async_phi_access decorator."""
        # Mock the audit logger
        with patch(
            "app.infrastructure.logging.audit.get_audit_logger"
        ) as mock_get_logger:
            mock_audit_logger = MagicMock()
            mock_get_logger.return_value = mock_audit_logger

            # Define a test async function with the decorator
            @audit_async_phi_access(resource_type="medical_record", action="update")
            async def update_medical_record(record_id, data):
                await asyncio.sleep(0.01)  # Simulate async operation
                return {"id": record_id, "updated": True, "data": data}

            # Set user context
            set_current_user("doctor_jones", "treatment")

            # Call the decorated function
            result = await update_medical_record(
                "record123", {"notes": "Patient improving"}
            )

            # Verify the function worked
            assert result["id"] == "record123"
            assert result["updated"] is True

            # Verify audit logs
            assert mock_audit_logger.log_data_modification.call_count == 2

            # Check first call (initiated)
            init_call_args = mock_audit_logger.log_data_modification.call_args_list[0][
                1
            ]
            assert init_call_args["user_id"] == "doctor_jones"
            assert init_call_args["action"] == "update"
            assert init_call_args["entity_type"] == "medical_record"
            assert init_call_args["entity_id"] == "record123"
            assert init_call_args["status"] == "initiated"

            # Check second call (success)
            success_call_args = mock_audit_logger.log_data_modification.call_args_list[
                1
            ][1]
            assert success_call_args["status"] == "success"

    @pytest.mark.asyncio
    async def test_audit_async_phi_access_with_exception(self):
        """Test the audit_async_phi_access decorator when the function raises an exception."""
        # Mock the audit logger
        with patch(
            "app.infrastructure.logging.audit.get_audit_logger"
        ) as mock_get_logger:
            mock_audit_logger = MagicMock()
            mock_get_logger.return_value = mock_audit_logger

            # Define a test async function with the decorator that raises an exception
            @audit_async_phi_access(resource_type="medical_record", action="update")
            async def update_medical_record_with_error(record_id):
                await asyncio.sleep(0.01)  # Simulate async operation
                raise ValueError("Async test error")

            # Set user context
            set_current_user("doctor_jones", "treatment")

            # Call the decorated function and expect an exception
            with pytest.raises(ValueError, match="Async test error"):
                await update_medical_record_with_error("record123")

            # Verify audit logs
            assert mock_audit_logger.log_data_modification.call_count == 2

            # Check first call (initiated)
            init_call_args = mock_audit_logger.log_data_modification.call_args_list[0][
                1
            ]
            assert init_call_args["status"] == "initiated"

            # Check second call (failed)
            failed_call_args = mock_audit_logger.log_data_modification.call_args_list[
                1
            ][1]
            assert failed_call_args["status"] == "failed"
            assert "Async test error" in failed_call_args["details"]
