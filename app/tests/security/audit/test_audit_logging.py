#!/usr/bin/env python3
"""
HIPAA Audit Logging Security Tests

Tests the audit logging system for HIPAA compliance (§164.312(b) - Audit controls).
"""

import json
import uuid
from datetime import datetime

import pytest

# Test data
TEST_USER = {
    "user_id": str(uuid.uuid4()),
    "username": "doctor_smith",
    "role": "doctor"
}

TEST_PATIENT = {
    "patient_id": str(uuid.uuid4()),
    "name": "Test Patient"
}


@pytest.mark.venv_only()
class TestAuditLogging:
    """Test the audit logging system for HIPAA compliance"""

    @pytest.fixture
    def audit_logger(self):
        """Return the audit logger to test"""
        try:
            from app.infrastructure.security.audit_logger import AuditLogger
            return AuditLogger()
        except ImportError:
            pytest.skip("Audit logger not implemented yet")

    def test_log_phi_access(self, audit_logger):
        """Test logging of PHI access events"""
        # Log PHI access
        log_id = audit_logger.log_phi_access(
            user_id=TEST_USER["user_id"],
            resource_type="patient_record",
            resource_id=TEST_PATIENT["patient_id"],
            action="view",
            reason="treatment"
        )

        # Verify log was created
        assert log_id is not None, "Failed to create audit log"

        # Retrieve log
        log_entry = audit_logger.get_log_entry(log_id)

        # Check required HIPAA fields
        assert log_entry["user_id"] == TEST_USER["user_id"], "Missing user ID in audit log"
        assert log_entry["resource_type"] == "patient_record", "Missing resource type in audit log"
        assert log_entry["resource_id"] == TEST_PATIENT["patient_id"], "Missing resource ID in audit log"
        assert log_entry["action"] == "view", "Missing action in audit log"
        assert log_entry["reason"] == "treatment", "Missing access reason in audit log"
        assert "timestamp" in log_entry, "Missing timestamp in audit log"
        assert "ip_address" in log_entry, "Missing IP address in audit log"

    def test_search_audit_logs(self, audit_logger):
        """Test searching audit logs"""
        # Create multiple log entries
        for action in ["view", "update", "print"]:
            audit_logger.log_phi_access(
                user_id=TEST_USER["user_id"],
                resource_type="patient_record",
                resource_id=TEST_PATIENT["patient_id"],
                action=action,
                reason="treatment"
            )

        # Search by user
        user_logs = audit_logger.search_logs(user_id=TEST_USER["user_id"])
        assert len(user_logs) >= 3, "Failed to retrieve logs by user ID"

        # Search by patient (resource)
        patient_logs = audit_logger.search_logs(resource_id=TEST_PATIENT["patient_id"])
        assert len(patient_logs) >= 3, "Failed to retrieve logs by patient ID"

        # Search by action
        view_logs = audit_logger.search_logs(action="view")
        assert len(view_logs) >= 1, "Failed to retrieve logs by action"

        # Search by date range
        now = datetime.now()
        recent_logs = audit_logger.search_logs(
            start_date=now.replace(hour=0, minute=0, second=0),
            end_date=now
        )
        assert len(recent_logs) >= 3, "Failed to retrieve logs by date range"

    def test_tamper_resistance(self, audit_logger):
        """Test audit log tamper resistance"""
        # Create log entry
        log_id = audit_logger.log_phi_access(
            user_id=TEST_USER["user_id"],
            resource_type="patient_record",
            resource_id=TEST_PATIENT["patient_id"],
            action="view",
            reason="treatment"
        )

        # Verify log integrity
        is_valid = audit_logger.verify_log_integrity(log_id)
        assert is_valid, "Log integrity check failed for untampered log"

        # Attempt to modify log (should fail or be detected)
        try:
            # This should either fail or create a detectable change
            modified = audit_logger.modify_log_entry_for_testing(log_id, {"action": "MODIFIED"})

            # If modification was allowed, integrity check should detect it
            if modified:
                is_valid = audit_logger.verify_log_integrity(log_id)
                assert not is_valid, "Tampered log passed integrity check"
        except Exception as e:
            # If modification throws exception, that's also acceptable
            assert "permission" in str(e).lower() or "tamper" in str(e).lower() or "read" in str(e).lower(), "Expected permission or tampering error"

    def test_log_security(self, audit_logger):
        """Test audit log security controls"""
        # Verify admin can access logs
        admin_access = audit_logger.check_log_access(
            user_id=str(uuid.uuid4()),  # Admin user
            role="admin"
        )
        assert admin_access, "Admin should have access to audit logs"

        # Verify doctor cannot access all logs
        doctor_access = audit_logger.check_log_access(
            user_id=TEST_USER["user_id"],
            role="doctor"
        )
        assert not doctor_access or doctor_access == "limited", "Doctor should have limited or no access to audit logs"

        # Verify patient cannot access logs
        patient_access = audit_logger.check_log_access(
            user_id=str(uuid.uuid4()),  # Patient user
            role="patient"
        )
        assert not patient_access, "Patients should not have access to audit logs"

    def test_log_export(self, audit_logger):
        """Test audit log export for compliance reporting"""
        # Create test logs
        for i in range(5):
            audit_logger.log_phi_access(
                user_id=TEST_USER["user_id"],
                resource_type="patient_record",
                resource_id=TEST_PATIENT["patient_id"],
                action="view",
                reason="treatment"
            )

        # Test export functionality
        export_file = audit_logger.export_logs(
            start_date=datetime.now().replace(hour=0, minute=0, second=0),
            end_date=datetime.now(),
            format="json"
        )

        assert export_file is not None, "Failed to export audit logs"

        # Verify export contains expected data
        with open(export_file) as f:
            exported_logs = json.load(f)

        assert len(exported_logs) >= 5, "Exported logs missing entries"
        assert all("user_id" in log for log in exported_logs), "Exported logs missing user ID"
        assert all("timestamp" in log for log in exported_logs), "Exported logs missing timestamp"
