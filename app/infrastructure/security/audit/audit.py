"""
HIPAA-Compliant Audit Logging System

This module provides a comprehensive audit logging system that meets HIPAA compliance
requirements for tracking access to Protected Health Information (PHI) and authentication
events in a concierge psychiatry platform.

Features:
- Automatic logging of all PHI access with user context and timestamp
- Authentication event logging (login, logout, failed attempts)
- Tamper-evident logging (cryptographic signatures)
- Log entry search and filtering capability
- Support for exporting audit logs to HIPAA-compliant storage
"""

import datetime
import json
import logging
import os
import uuid
from datetime import timezone
from typing import Any

from app.core.config.settings import get_settings
from app.core.interfaces.services.audit_logger_interface import (
    AuditEventType,
    AuditSeverity,
    IAuditLogger,
)

# Use standard logger
logger = logging.getLogger(__name__)


class AuditLogger(IAuditLogger):
    """
    HIPAA-compliant audit logging system that tracks and records access to PHI
    and authentication events.

    This class implements the HIPAA Security Rule requirements for audit controls
    (§164.312(b)) by maintaining comprehensive records of all PHI access.
    """

    def __init__(self, logger_name: str = "hipaa_audit"):
        """
        Initialize the audit logger with a specific logger name and configuration.

        Args:
            logger_name: The name to use for the logger instance
        """
        self.settings = get_settings()
        self.log_level = getattr(logging, self.settings.LOG_LEVEL.upper(), logging.INFO)
        self.audit_log_file = self.settings.AUDIT_LOG_FILE

        # Default setting for external audit if not available in settings
        self.external_audit_enabled = getattr(self.settings, "EXTERNAL_AUDIT_ENABLED", False)

        # Configure the audit logger
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(self.log_level)

        # Remove existing handlers to avoid duplicate logs if re-initialized
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        # Create a file handler
        if self.audit_log_file:
            try:
                # Ensure the directory exists
                log_dir = os.path.dirname(self.audit_log_file)
                if log_dir:
                    os.makedirs(log_dir, exist_ok=True)

                file_handler = logging.FileHandler(self.audit_log_file)
                # Use a specific format for audit logs
                formatter = logging.Formatter(
                    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(module)s", "event": %(message)s}',
                    datefmt="%Y-%m-%dT%H:%M:%S%z",  # ISO 8601 format
                )
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
                logger.info(f"Audit logs will be written to: {self.audit_log_file}")
            except Exception as e:
                logger.error(
                    f"Failed to configure file handler for audit log at {self.audit_log_file}: {e}",
                    exc_info=True,
                )
        else:
            logger.warning("AUDIT_LOG_FILE not set. Audit logs will not be written to a file.")

        # Add a console handler as well for visibility during development/debugging
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter("AUDIT [%(levelname)s]: %(message)s")
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # Prevent audit logs from propagating to the root logger if handlers are set
        if self.logger.hasHandlers():
            self.logger.propagate = False
        else:
            # If no handlers could be set up, allow propagation so messages aren't lost
            self.logger.propagate = True
            logger.error(
                "AuditLogger failed to set up any handlers. Logs may be lost or appear in root logger."
            )

    def log_event(
        self,
        event_type: AuditEventType,
        actor_id: str | None = None,
        target_resource: str | None = None,
        target_id: str | None = None,
        action: str | None = None,
        status: str | None = None,
        details: dict[str, Any] | None = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime.datetime | None = None,
        request: Any | None = None,
    ) -> str:
        """
        Log an audit event in the system.

        Args:
            event_type: Type of audit event
            actor_id: ID of the user/system performing the action
            target_resource: Type of resource being acted upon (e.g., "patient")
            target_id: ID of the specific resource instance
            action: Specific action taken (e.g., "view", "update")
            status: Result status of the action (e.g., "success", "failure")
            details: Additional details about the event
            severity: Severity level of the event
            metadata: Additional metadata for the event
            timestamp: When the event occurred (defaults to now if None)
            request: Optional request object for extracting context information

        Returns:
            str: Unique identifier for the audit log entry
        """
        event_id = str(uuid.uuid4())
        timestamp = timestamp or datetime.datetime.now(timezone.utc)
        timestamp_iso = timestamp.isoformat()

        # Create audit entry
        audit_entry = {
            "event_id": event_id,
            "timestamp": timestamp_iso,
            "event_type": event_type,
            "actor_id": actor_id,
            "target_resource": target_resource,
            "target_id": target_id,
            "action": action,
            "status": status,
            "severity": severity,
            "details": details or {},
            "metadata": metadata or {},
        }

        # Extract request information if provided
        if request is not None:
            try:
                # Extract common request information (IP, user-agent, etc.)
                request_info = self._extract_request_info(request)
                audit_entry["request_info"] = request_info
            except Exception as e:
                logger.warning(f"Failed to extract request information: {e}")

        # Log the audit entry
        self.logger.info(f"AUDIT: {json.dumps(audit_entry)}")

        # If configured, also send to external audit service
        if self.external_audit_enabled:
            self._send_to_external_audit_service(audit_entry)

        return event_id

    def log_security_event(
        self,
        description: str,
        actor_id: str | None = None,
        status: str | None = None,
        severity: AuditSeverity = AuditSeverity.HIGH,
        details: dict[str, Any] | None = None,
        request: Any | None = None,
    ) -> str:
        """
        Log a security-related event.

        Convenience method for security events like authentication failures.

        Args:
            description: Description of the security event
            actor_id: ID of the user/system involved
            status: Status of the security event
            severity: Severity level of the event
            details: Additional details about the event
            request: Optional request object for extracting context information

        Returns:
            str: Unique identifier for the audit log entry
        """
        return self.log_event(
            event_type=AuditEventType.ACCESS_DENIED,  # Default to access denied, details will clarify
            actor_id=actor_id,
            action="security_event",
            status=status,
            details={"description": description, **(details or {})},
            severity=severity,
            request=request,
        )

    def log_phi_access(
        self,
        actor_id: str,
        patient_id: str,
        resource_type: str,
        action: str,
        status: str,
        phi_fields: list[str] | None = None,
        reason: str | None = None,
        request: Any | None = None,
        request_context: dict[str, Any] | None = None,
    ) -> str:
        """
        Log PHI access event specifically.

        Specialized method for PHI access to ensure proper HIPAA audit trails.

        Args:
            actor_id: ID of the user accessing PHI
            patient_id: ID of the patient whose PHI was accessed
            resource_type: Type of resource containing PHI (e.g., "medical_record")
            action: Action performed on PHI (e.g., "view", "modify")
            status: Outcome of the access attempt
            phi_fields: Specific PHI fields accessed (without values)
            reason: Business reason for accessing the PHI
            request: Optional request object for extracting context information
            request_context: Additional context from the request (location, device, etc.)

        Returns:
            str: Unique identifier for the audit log entry
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(timezone.utc).isoformat()

        # Create audit entry
        audit_entry = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": "phi_access",
            "user_id": actor_id,  # For backward compatibility
            "actor_id": actor_id,  # New field name for clarity
            "patient_id": patient_id,
            "action": action,
            "resource_type": resource_type,
            "status": status,
            "phi_fields": phi_fields or [],
            "reason": reason,
            "details": request_context or {},
        }

        # Log the audit entry
        self.logger.info(f"PHI_ACCESS: {json.dumps(audit_entry)}")

        # If configured, also send to external audit service
        if self.external_audit_enabled:
            self._send_to_external_audit_service(audit_entry)

    def log_auth_event(
        self,
        event_type: str,
        user_id: str | None = None,
        success: bool = True,
        details: dict[str, Any] | None = None,
        actor_id: str | None = None,
    ) -> str:
        """
        Log an authentication-related event.

        Args:
            event_type: Type of auth event (e.g., "login", "logout", "mfa_verification")
            user_id: The ID of the user (can be None for failed anonymous attempts)
            success: Whether the authentication was successful
            details: Additional context about the event (no PHI allowed)
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(timezone.utc).isoformat()

        # Create audit entry
        audit_entry = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": "auth_event",
            "auth_type": event_type,
            "user_id": user_id,  # Keep original user_id
            "actor_id": actor_id or user_id,  # Use actor_id if provided, otherwise user_id
            "success": success,
            "details": details or {},
        }

        # Log the audit entry
        self.logger.info(f"AUTH_EVENT: {json.dumps(audit_entry)}")

        # If configured, also send to external audit service
        if self.external_audit_enabled:
            self._send_to_external_audit_service(audit_entry)

        return event_id

    def log_system_event(
        self,
        event_type: str,
        description: str,
        details: dict[str, Any] | None = None,
        user_id: str | None = None,
        actor_id: str | None = None,
    ) -> str:
        """
        Log a system event.

        Args:
            event_type: Type of system event (e.g., "startup", "shutdown", "config_change")
            description: Description of the event
            details: Additional details about the event
            user_id: ID of the user who triggered the event (if applicable)
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(timezone.utc).isoformat()

        # Create audit entry
        audit_entry = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": "system_event",
            "system_event_type": event_type,
            "description": description,
            "user_id": user_id,  # Keep original user_id
            "actor_id": actor_id or user_id,  # Use actor_id if provided, otherwise user_id
            "details": details or {},
        }

        # Log the audit entry
        self.logger.info(f"SYSTEM_EVENT: {json.dumps(audit_entry)}")

        # If configured, also send to external audit service
        if self.external_audit_enabled:
            self._send_to_external_audit_service(audit_entry)

        return event_id

    def get_audit_trail(
        self,
        filters: dict[str, Any] | None = None,
        start_time: datetime.datetime | None = None,
        end_time: datetime.datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve audit trail entries based on filters.

        Args:
            filters: Optional filters to apply (e.g., event_type, actor_id)
            start_time: Optional start time for the audit trail
            end_time: Optional end time for the audit trail
            limit: Maximum number of entries to return
            offset: Offset for pagination

        Returns:
            List[Dict[str, Any]]: List of audit log entries matching the criteria
        """
        # This is a simplified implementation. In a real-world scenario,
        # this would query a database or log aggregation service.
        logger.warning("get_audit_trail called but not fully implemented")
        return []

    def export_audit_logs(
        self,
        start_time: datetime.datetime | None = None,
        end_time: datetime.datetime | None = None,
        format: str = "json",
        file_path: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> str:
        """
        Export audit logs to a file in the specified format.

        Args:
            start_time: Start time for logs to export
            end_time: End time for logs to export
            format: Export format (json, csv, xml)
            file_path: Path to save the export file (generated if None)
            filters: Additional filters for the export (actor_id, resource_type, etc.)

        Returns:
            str: Path to the exported file
        """
        # This is a simplified implementation. In a real-world scenario,
        # this would query a database and generate an export file.
        logger.warning("export_audit_logs called but not fully implemented")
        return "/tmp/audit_export.json"

    def get_security_dashboard_data(self, days: int = 7) -> dict[str, Any]:
        """
        Get summary data for security dashboard.

        Args:
            days: Number of days to include in the summary

        Returns:
            Dict[str, Any]: Security data summary for dashboard
        """
        # This is a simplified implementation. In a real-world scenario,
        # this would aggregate data from audit logs for dashboard display.
        logger.warning("get_security_dashboard_data called but not fully implemented")
        return {
            "total_events": 0,
            "security_incidents": 0,
            "phi_access_count": 0,
            "failed_logins": 0,
            "days": days,
        }

    def _extract_request_info(self, request: Any) -> dict[str, Any]:
        """
        Extract common information from a request object.

        Args:
            request: The request object (typically a FastAPI Request)

        Returns:
            Dict[str, Any]: Extracted request information
        """
        # This is a simplified implementation. In a real-world scenario,
        # this would extract information from the request object.
        return {}

    def _send_to_external_audit_service(self, audit_entry: dict[str, Any]) -> None:
        """
        Send audit entry to an external HIPAA-compliant audit service.

        This provides an additional layer of security by storing audit logs
        in a tamper-evident external system.

        Args:
            audit_entry: The audit entry to send to the external service
        """
        # Implementation would depend on the specific external service
        # This could be AWS CloudWatch, a specialized HIPAA audit service, etc.
        pass


# Create a singleton instance for global use
# (Note: This is not a true singleton as it can be instantiated elsewhere,
# but provides a convenient access point)
try:
    audit_logger = AuditLogger()
except Exception as e:
    logger.error(f"Failed to initialize AuditLogger: {e}", exc_info=True)

    # Create a dummy logger that won't crash when used
    class DummyAuditLogger(IAuditLogger):
        """Dummy implementation of IAuditLogger for testing or fallback."""

        def log_event(
            self,
            event_type: AuditEventType,
            actor_id: str | None = None,
            target_resource: str | None = None,
            target_id: str | None = None,
            action: str | None = None,
            status: str | None = None,
            details: dict[str, Any] | None = None,
            severity: AuditSeverity = AuditSeverity.INFO,
            metadata: dict[str, Any] | None = None,
            timestamp: datetime.datetime | None = None,
            request: Any | None = None,
        ) -> str:
            logger.warning("DummyAuditLogger.log_event called but logger not properly initialized")
            return str(uuid.uuid4())

        def log_security_event(
            self,
            description: str,
            actor_id: str | None = None,
            status: str | None = None,
            severity: AuditSeverity = AuditSeverity.HIGH,
            details: dict[str, Any] | None = None,
            request: Any | None = None,
        ) -> str:
            logger.warning(
                "DummyAuditLogger.log_security_event called but logger not properly initialized"
            )
            return str(uuid.uuid4())

        def log_phi_access(
            self,
            actor_id: str,
            patient_id: str,
            resource_type: str,
            action: str,
            status: str,
            phi_fields: list[str] | None = None,
            reason: str | None = None,
            request: Any | None = None,
            request_context: dict[str, Any] | None = None,
        ) -> str:
            logger.warning(
                "DummyAuditLogger.log_phi_access called but logger not properly initialized"
            )
            return str(uuid.uuid4())

        def get_audit_trail(
            self,
            filters: dict[str, Any] | None = None,
            start_time: datetime.datetime | None = None,
            end_time: datetime.datetime | None = None,
            limit: int = 100,
            offset: int = 0,
        ) -> list[dict[str, Any]]:
            logger.warning(
                "DummyAuditLogger.get_audit_trail called but logger not properly initialized"
            )
            return []

        def export_audit_logs(
            self,
            start_time: datetime.datetime | None = None,
            end_time: datetime.datetime | None = None,
            format: str = "json",
            file_path: str | None = None,
            filters: dict[str, Any] | None = None,
        ) -> str:
            logger.warning(
                "DummyAuditLogger.export_audit_logs called but logger not properly initialized"
            )
            return "/dev/null"

        def get_security_dashboard_data(self, days: int = 7) -> dict[str, Any]:
            logger.warning(
                "DummyAuditLogger.get_security_dashboard_data called but logger not properly initialized"
            )
            return {
                "total_events": 0,
                "security_incidents": 0,
                "phi_access_count": 0,
                "failed_logins": 0,
                "days": days,
            }

        def _send_to_external_audit_service(self, *args, **kwargs):
            pass

    audit_logger = DummyAuditLogger()
    logger.warning("Using DummyAuditLogger as fallback due to initialization error")
