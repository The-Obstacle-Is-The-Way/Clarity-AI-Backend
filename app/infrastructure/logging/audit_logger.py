"""
HIPAA-compliant audit logging for the Novamind Digital Twin Platform.

This module provides comprehensive audit logging for all PHI access and
modifications, ensuring compliance with HIPAA Security Rule § 164.312(b).
"""

import json
import logging
import os
import re
import tempfile
import uuid
from typing import Any, Dict, Optional
from datetime import date

from app.core.interfaces.services.audit_logger_interface import (
    IAuditLogger,
    AuditEventType,
    AuditSeverity,
)
from app.core.utils.date_utils import utcnow, format_date_iso

# Corrected import path
# from app.config.settings import settings # Keep only get_settings
from app.core.config.settings import get_settings

# Load settings once
settings = get_settings()

# Import settings with fallback for tests
try:
    AUDIT_ENABLED = settings.DATABASE_AUDIT_ENABLED  # Use loaded settings
    AUDIT_LOG_DIR = settings.AUDIT_LOG_FILE  # Use main AUDIT_LOG_FILE setting
except (ImportError, AttributeError):
    # Fallback for tests
    AUDIT_ENABLED = True
    AUDIT_LOG_DIR = os.path.join(tempfile.gettempdir(), "novamind_audit")

from pydantic import BaseModel, Field, field_validator

from app.core.domain.entities.user import User, UserRole


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

    @classmethod
    def setup(cls, log_dir: str | None = None) -> None:
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
            os.makedirs(audit_log_dir, exist_ok=True)

            # Create a file handler for the audit log
            today = date.today()
            audit_file = os.path.join(
                audit_log_dir, f"hipaa_audit_{today.isoformat()}.log"
            )
            handler = logging.FileHandler(audit_file)
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
    def log_transaction(cls, metadata: dict[str, Any]) -> None:
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

    @classmethod
    def log_phi_access(
        cls,
        user_id: str,
        patient_id: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Log PHI access for audit purposes.

        Args:
            user_id: ID of the user accessing the PHI
            patient_id: ID of the patient whose PHI was accessed
            action: Type of access (read, write, delete)
            details: Additional details about the access
        """
        metadata = {
            "user_id": user_id,
            "patient_id": patient_id,
            "action": action,
            "timestamp": format_date_iso(utcnow()),
            "details": details or {},
        }

        cls.log_transaction(metadata)

    @classmethod
    def log_security_event(
        cls,
        event_type: str,
        user_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Log a security event for audit purposes.

        Args:
            event_type: Type of security event
            user_id: ID of the user involved (if applicable)
            details: Additional details about the event
        """
        metadata = {
            "event_type": event_type,
            "user_id": user_id or "system",
            "action": "security_event",
            "timestamp": format_date_iso(utcnow()),
            "details": details or {},
        }

        cls.log_transaction(metadata)

        # Log at appropriate level based on event type
        if event_type in [
            "authentication_failure",
            "authorization_failure",
            "tampering_detected",
        ]:
            cls._logger.warning(f"SECURITY_EVENT: {json.dumps(metadata)}")
        else:
            cls._logger.info(f"SECURITY_EVENT: {json.dumps(metadata)}")


# Initialize the audit logger when the module is imported - but defer actual setup
# to ensure we don't have issues during import for tests
AuditLogger._configured = False

# ---------------------------------------------------------------------------
# Convenience aliases for legacy test‑suite compatibility
# ---------------------------------------------------------------------------

# A large portion of the legacy and security‑focused test‑suite expects the
# module itself (i.e. ``app.infrastructure.logging.audit_logger``) to expose
# *functions* named ``log_phi_access`` and ``log_security_event`` that delegate
# to the corresponding ``AuditLogger`` class methods.  Export thin wrappers so
# we don't have to refactor every single test file:


def log_phi_access(*args, **kwargs):  # type: ignore[missing-return-type-doc]
    """Convenience alias for AuditLogger.log_phi_access."""
    return AuditLogger.log_phi_access(*args, **kwargs)


def audit_log_phi_access(
    user_id: str, patient_id: str, action: str, details: dict[str, Any] | None = None
) -> None:
    """
    Log PHI access for audit purposes.

    This is an alias for AuditLogger.log_phi_access to maintain compatibility
    with imports from different parts of the codebase.

    Args:
        user_id: ID of the user accessing the PHI
        patient_id: ID of the patient whose PHI was accessed
        action: Type of access (read, write, delete)
        details: Additional details about the access
    """
    return AuditLogger.log_phi_access(user_id, patient_id, action, details)


def log_security_event(*args, **kwargs):  # type: ignore[missing-return-type-doc]
    """Convenience alias for AuditLogger.log_security_event."""
    return AuditLogger.log_security_event(*args, **kwargs)


# Explicit re‑export so ``from app.infrastructure.logging.audit_logger import
# log_phi_access`` resolves correctly without requiring an intermediate import
# of *AuditLogger*.

__all__ = [
    "AuditLogger",
    "log_phi_access",
    "log_security_event",
    "log_audit_event",
    "AuditEventType",
    "AuditSeverity",
    "IAuditLogger",
]
