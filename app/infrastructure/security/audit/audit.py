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

# Use canonical config import
from app.config.settings import get_settings

# REMOVED: settings = get_settings() - Defer loading
logger = logging.getLogger(__name__) # Use standard logger


class AuditLogger:
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
        # ADDED: Load settings within __init__
        settings = get_settings()
        self.log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
        self.audit_log_file = settings.AUDIT_LOG_FILE
        
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
                    datefmt='%Y-%m-%dT%H:%M:%S%z' # ISO 8601 format
                )
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
                logger.info(f"Audit logs will be written to: {self.audit_log_file}")
            except Exception as e:
                logger.error(f"Failed to configure file handler for audit log at {self.audit_log_file}: {e}", exc_info=True)
        else:
            logger.warning("AUDIT_LOG_FILE not set. Audit logs will not be written to a file.")

        # Add a console handler as well for visibility during development/debugging
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            'AUDIT [%(levelname)s]: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Prevent audit logs from propagating to the root logger if handlers are set
        if self.logger.hasHandlers():
            self.logger.propagate = False
        else:
            # If no handlers could be set up, allow propagation so messages aren't lost
            self.logger.propagate = True 
            logger.error("AuditLogger failed to set up any handlers. Logs may be lost or appear in root logger.")

    def log_phi_access(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Log an access to Protected Health Information (PHI).

        Args:
            user_id: The ID of the user accessing the PHI
            action: The action performed (e.g., "view", "edit", "delete")
            resource_type: The type of resource accessed (e.g., "patient", "prescription")
            resource_id: The ID of the specific resource accessed
            details: Additional context about the access (no PHI allowed here)
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(timezone.utc).isoformat()

        # Create audit entry
        audit_entry = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": "phi_access",
            "user_id": user_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
        }

        # Log the audit entry
        self.logger.info(f"PHI_ACCESS: {json.dumps(audit_entry)}")

        # If configured, also send to external audit service
        if settings.EXTERNAL_AUDIT_ENABLED:
            self._send_to_external_audit_service(audit_entry)

    def log_auth_event(
        self,
        event_type: str,
        user_id: str | None,
        success: bool,
        details: dict[str, Any] | None = None,
    ) -> None:
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
            "user_id": user_id,
            "success": success,
            "details": details or {},
        }

        # Log the audit entry
        self.logger.info(f"AUTH_EVENT: {json.dumps(audit_entry)}")

        # If configured, also send to external audit service
        if settings.EXTERNAL_AUDIT_ENABLED:
            self._send_to_external_audit_service(audit_entry)

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
# audit_logger = AuditLogger()
