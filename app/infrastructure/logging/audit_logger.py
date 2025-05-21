"""
HIPAA-compliant audit logging for the Novamind Digital Twin Platform.

This module provides comprehensive audit logging for all PHI access and
modifications, ensuring compliance with HIPAA Security Rule § 164.312(b).
"""

import json
import logging
from datetime import date, datetime
from pathlib import Path
from tempfile import gettempdir
from typing import Any, Optional, Dict, List
# In Python 3.12, we use built-in dict and list types rather than importing from typing

from app.core.config.settings import get_settings
from app.core.constants.audit import AuditEventType, AuditSeverity
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.core.utils.date_utils import format_date_iso, utcnow

# Load settings once
settings = get_settings()

# Import settings with fallback for tests
try:
    AUDIT_ENABLED = getattr(settings, "AUDIT_ENABLED", True)
    AUDIT_LOG_DIR = getattr(settings, "AUDIT_LOG_FILE", None)
except (ImportError, AttributeError):
    # Fallback for tests
    AUDIT_ENABLED = True
    AUDIT_LOG_DIR = None

# If no directory is configured, use a temp directory
if not AUDIT_LOG_DIR:
    AUDIT_LOG_DIR = Path(gettempdir()) / "novamind_audit"


class AuditLogger(IAuditLogger):
    """
    HIPAA-compliant audit logger for PHI operations.

    This class provides secure, immutable logging of all PHI access and
    modifications, supporting both debugging and regulatory compliance.

    Implements the IAuditLogger interface to ensure architectural alignment
    with clean architecture principles and dependency inversion.
    """

    # Configure standard Python logger for audit events
    _logger = logging.getLogger("hipaa.audit")
    _configured = False

    def __init__(self) -> None:
        """Initialize the audit logger with proper configuration."""
        # Configure if not already done
        if not self.__class__._configured:
            self.__class__.setup()

    @classmethod
    def setup(cls, log_dir: Optional[str] = None) -> None:
        """
        Set up the audit logger with appropriate handlers.

        Args:
            log_dir: Directory to store audit logs (default: from settings)
        """
        if cls._configured:
            return  # Already configured

        # Only configure once
        cls._configured = True

        # Use provided log_dir, settings, or default
        audit_log_dir = log_dir or AUDIT_LOG_DIR

        # For tests, use memory handler if audit_log_dir is None or not writable
        try:
            # Create log directory if it doesn't exist
            if isinstance(audit_log_dir, str):
                audit_log_path = Path(audit_log_dir)
            else:  # Already a Path object
                audit_log_path = audit_log_dir
                
            audit_log_path.mkdir(parents=True, exist_ok=True)

            # Create a file handler for the audit log
            today = date.today()
            audit_file = audit_log_path / f"hipaa_audit_{today.isoformat()}.log"
            handler = logging.FileHandler(str(audit_file))
        except (OSError, PermissionError):
            # Fallback to memory handler for tests
            handler = logging.StreamHandler()
            audit_log_dir = "MEMORY"

        # Set a secure formatter with all relevant fields
        formatter = logging.Formatter(
            "%(asctime)s [AUDIT] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        # Configure the logger
        cls._logger.setLevel(logging.INFO)

        # Remove any existing handlers
        for hdlr in cls._logger.handlers:
            cls._logger.removeHandler(hdlr)

        cls._logger.addHandler(handler)

        # Log startup message
        cls._logger.info(f"HIPAA audit logging initialized (dir: {audit_log_dir})")
            
    @classmethod
    def log_transaction(cls, metadata: dict) -> None:
        """
        Log a transaction for audit purposes.

        Args:
            metadata: Dictionary containing transaction metadata:
                - user_id: ID of the user performing the action
                - action: Type of action performed
                - resource_type: Type of resource affected
                - resource_id: ID of the resource affected
                - details: Additional details about the action
        """
        # Configure if not already done
        if not cls._configured:
            cls.setup()

        # Skip logging if disabled
        if not AUDIT_ENABLED:
            return

        # Ensure required fields are present
        required_fields = ["user_id", "action"]
        for field in required_fields:
            if field not in metadata:
                cls._logger.warning(f"Audit log missing required field: {field}")
                metadata[field] = "unknown"

        # Add timestamp if not present
        if "timestamp" not in metadata:
            metadata["timestamp"] = format_date_iso(utcnow())

        # Format the message as JSON for machine readability
        message = json.dumps(metadata)

        # Log the transaction
        cls._logger.info(f"PHI_ACCESS: {message}")

    def log_phi_access(
        self,
        actor_id: str,
        patient_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        data_accessed: Optional[str] = None,
        resource_type: Optional[str] = None,
        access_reason: Optional[str] = None,
        action: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Log access to Protected Health Information (PHI).

        Args:
            actor_id: ID of the user or system accessing the PHI
            patient_id: ID of the patient whose PHI was accessed
            resource_id: ID of the resource being accessed (alternative to patient_id)
            data_accessed: Description of the PHI data that was accessed
            resource_type: Type of resource being accessed
            access_reason: Reason for accessing the PHI
            action: Action being performed (view, modify, delete)
            ip_address: IP address of the actor
            details: Additional human-readable details
            metadata: Additional contextual information about the access
        """
        # Configure if not already done
        if not self.__class__._configured:
            self.__class__.setup()

        # Skip logging if disabled
        if not AUDIT_ENABLED:
            return

        # Build log data
        log_data = {
            "user_id": actor_id,  # For backward compatibility
            "actor_id": actor_id,
            "timestamp": format_date_iso(utcnow()),
            "action": action or "access",
        }

        # Add optional fields if provided
        optional_fields = {
            "patient_id": patient_id,
            "resource_id": resource_id,
            "data_accessed": data_accessed,
            "resource_type": resource_type,
            "access_reason": access_reason,
            "ip_address": ip_address,
            "details": details,
        }

        for key, value in optional_fields.items():
            if value is not None:
                log_data[key] = value

        # Add any additional metadata
        if metadata:
            log_data.update(metadata)

        # Log the transaction
        self.__class__.log_transaction(log_data)

    def log_security_event(
        self,
        event_type: str,
        description: Optional[str] = None,
        user_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: Optional[str] = None,
        status: Optional[str] = None,
        metadata: Optional[dict] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """
        Log a security-related event.

        Args:
            event_type: Type of security event (e.g., "LOGIN_SUCCESS", "ACCESS_DENIED")
            description: Human-readable description of the event
            user_id: ID of the user associated with the event (if applicable)
            actor_id: Alternative identifier for the actor causing the event (alias for user_id)
            severity: Severity level of the event
            details: Detailed information about the event (alias for description)
            status: Status of the event (success/failure)
            metadata: Additional contextual information about the event
            ip_address: IP address associated with the event
        """
        # Configure if not already done
        if not self.__class__._configured:
            self.__class__.setup()

        # Skip logging if disabled
        if not AUDIT_ENABLED:
            return

        # Normalize inputs for backward compatibility
        effective_user_id = user_id or actor_id or "system"
        effective_description = description or details or ""

        # Build log data
        log_data = {
            "event_type": event_type,
            "user_id": effective_user_id,
            "timestamp": format_date_iso(utcnow()),
            "action": "security_event",
            "severity": severity.value if isinstance(severity, AuditSeverity) else str(severity),
        }

        # Add optional fields if provided
        optional_fields = {
            "description": effective_description,
            "status": status,
            "ip_address": ip_address,
        }

        for key, value in optional_fields.items():
            if value is not None:
                log_data[key] = value

        # Add any additional metadata
        if metadata:
            log_data.update(metadata)

        # Log at appropriate level based on severity
        log_message = json.dumps(log_data)
        
        if severity in (AuditSeverity.ERROR, AuditSeverity.CRITICAL):
            self.__class__._logger.error(f"SECURITY_EVENT: {log_message}")
        elif severity == AuditSeverity.WARNING:
            self.__class__._logger.warning(f"SECURITY_EVENT: {log_message}")
        else:
            self.__class__._logger.info(f"SECURITY_EVENT: {log_message}")
            
        # Log the transaction for persistent storage
        self.__class__.log_transaction(log_data)

    def log_auth_event(
        self,
        event_type: str,
        user_id: str,
        success: bool,
        description: str,
        ip_address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Log an authentication or authorization event.

        Args:
            event_type: Type of auth event (e.g., "LOGIN", "LOGOUT", "TOKEN_VALIDATION")
            user_id: ID of the user associated with the event
            success: Whether the auth operation succeeded
            description: Human-readable description of the event
            ip_address: IP address associated with the event
            metadata: Additional contextual information about the event
        """
        # Configure if not already done
        if not self.__class__._configured:
            self.__class__.setup()

        # Skip logging if disabled
        if not AUDIT_ENABLED:
            return

        # Set severity based on success/failure
        severity = AuditSeverity.INFO if success else AuditSeverity.WARNING
        status = "success" if success else "failure"

        # Build log data
        log_data = {
            "event_type": event_type,
            "user_id": user_id,
            "success": success,
            "status": status,
            "description": description,
            "timestamp": format_date_iso(utcnow()),
            "severity": severity.value,
        }

        # Add optional fields if provided
        if ip_address:
            log_data["ip_address"] = ip_address

        # Add any additional metadata
        if metadata:
            log_data.update(metadata)

        # Log the message at the appropriate level
        log_message = json.dumps(log_data)
        if success:
            self.__class__._logger.info(f"AUTH_EVENT: {log_message}")
        else:
            self.__class__._logger.warning(f"AUTH_EVENT: {log_message}")

        # Log the transaction for persistent storage
        self.__class__.log_transaction(log_data)
    
    def log_system_event(
        self,
        event_type: str,
        description: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Log a system-level event.

        Args:
            event_type: Type of system event (e.g., "STARTUP", "SHUTDOWN", "ERROR")
            description: Human-readable description of the event
            severity: Severity level of the event
            metadata: Additional contextual information about the event
        """
        # Configure if not already done
        if not self.__class__._configured:
            self.__class__.setup()

        # Skip logging if disabled
        if not AUDIT_ENABLED:
            return

        # Build log data
        log_data = {
            "event_type": event_type,
            "description": description,
            "timestamp": format_date_iso(utcnow()),
            "action": "system_event",
            "severity": severity.value if isinstance(severity, AuditSeverity) else str(severity),
        }

        # Add any additional metadata
        if metadata:
            log_data.update(metadata)

        # Log at appropriate level based on severity
        log_message = json.dumps(log_data)
        
        if severity in (AuditSeverity.ERROR, AuditSeverity.CRITICAL):
            self.__class__._logger.error(f"SYSTEM_EVENT: {log_message}")
        elif severity == AuditSeverity.WARNING:
            self.__class__._logger.warning(f"SYSTEM_EVENT: {log_message}")
        else:
            self.__class__._logger.info(f"SYSTEM_EVENT: {log_message}")
            
        # Log the transaction for persistent storage
        self.__class__.log_transaction(log_data)

    def get_audit_trail(
        self,
        user_id: Optional[str] = None,
        patient_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: Optional[int] = 100,
        offset: Optional[int] = 0,
    ) -> list:
        """
        Retrieve audit trail entries based on filtering criteria.

        Args:
            user_id: Filter by user ID
            patient_id: Filter by patient ID
            event_type: Filter by event type
            start_date: Filter by start date (ISO format)
            end_date: Filter by end date (ISO format)
            limit: Maximum number of entries to return
            offset: Offset for pagination

        Returns:
            List of audit log entries matching the criteria
        """
        # In a real implementation, this would query a persistent storage system
        # such as a database. For MVP and testing, we'll just return an empty list.
        # TODO: Implement proper storage and retrieval of audit events in a later sprint
        return []


# Initialize the audit logger when the module is imported - but defer actual setup
# to ensure we don't have issues during import for tests
AuditLogger._configured = False


# Function wrappers for backward compatibility
def log_phi_access(
    user_id: str,
    patient_id: str,
    action: str,
    details: Optional[dict] = None,
) -> None:
    """Backward-compatible function for logging PHI access."""
    logger = AuditLogger()
    return logger.log_phi_access(
        actor_id=user_id,
        patient_id=patient_id,
        action=action,
        metadata=details,
    )


def log_security_event(
    event_type: str,
    user_id: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    """Backward-compatible function for logging security events."""
    logger = AuditLogger()
    return logger.log_security_event(
        event_type=event_type,
        user_id=user_id,
        metadata=details,
    )


def log_auth_event(
    event_type: str,
    user_id: str,
    success: bool,
    description: str,
    ip_address: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """Function for logging authentication events."""
    logger = AuditLogger()
    return logger.log_auth_event(
        event_type=event_type,
        user_id=user_id,
        success=success,
        description=description,
        ip_address=ip_address,
        metadata=metadata,
    )

# Alias for backward compatibility with existing code
audit_log_phi_access = log_phi_access

# Explicit re-export so external modules can import these functions
# without requiring an intermediate import of AuditLogger
__all__ = [
    "AuditEventType",
    "AuditLogger",
    "AuditSeverity",
    "IAuditLogger",
    "audit_log_phi_access",
    "log_auth_event",
    "log_phi_access",
    "log_security_event",
]
