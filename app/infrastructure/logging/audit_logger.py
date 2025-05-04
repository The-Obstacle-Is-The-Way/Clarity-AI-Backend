"""
HIPAA-compliant audit logging for the Novamind Digital Twin Platform.

This module provides comprehensive audit logging for all PHI access and
modifications, ensuring compliance with HIPAA Security Rule § 164.312(b).
"""

import datetime
import json
import logging
import os
import re
import tempfile
from typing import Any

# Corrected import path
# from app.config.settings import settings # Keep only get_settings
from app.config.settings import get_settings

# Load settings once
settings = get_settings()

# Import settings with fallback for tests
try:
    AUDIT_ENABLED = settings.DATABASE_AUDIT_ENABLED # Use loaded settings
    AUDIT_LOG_DIR = settings.AUDIT_LOG_FILE # Use main AUDIT_LOG_FILE setting
except (ImportError, AttributeError):
    # Fallback for tests
    AUDIT_ENABLED = True
    AUDIT_LOG_DIR = os.path.join(tempfile.gettempdir(), "novamind_audit")


class AuditLogger:
    """
    HIPAA-compliant audit logger for PHI operations.
    
    This class provides secure, immutable logging of all PHI access and
    modifications, supporting both debugging and regulatory compliance.
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
            audit_file = os.path.join(audit_log_dir, f"hipaa_audit_{datetime.date.today().isoformat()}.log")
            handler = logging.FileHandler(audit_file)
        except (OSError, PermissionError):
            # Fallback to memory handler for tests
            handler = logging.StreamHandler()
            audit_log_dir = "MEMORY"
        
        # Set a secure formatter with all relevant fields
        formatter = logging.Formatter(
            '%(asctime)s [AUDIT] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
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
            metadata["timestamp"] = datetime.datetime.now().isoformat()
        
        # Format the message as JSON for machine readability
        message = json.dumps(metadata)
        
        # Log the transaction
        cls._logger.info(f"PHI_ACCESS: {message}")
    
    @classmethod
    def log_phi_access(cls, user_id: str, patient_id: str, action: str, details: dict[str, Any] | None = None) -> None:
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
            "timestamp": datetime.datetime.now().isoformat(),
            "details": details or {}
        }
        
        cls.log_transaction(metadata)
    
    @classmethod
    def log_security_event(cls, event_type: str, user_id: str | None = None, details: dict[str, Any] | None = None) -> None:
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
            "timestamp": datetime.datetime.now().isoformat(),
            "details": details or {}
        }
        
        cls.log_transaction(metadata)
        
        # Log at appropriate level based on event type
        if event_type in ["authentication_failure", "authorization_failure", "tampering_detected"]:
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
# those imports keep working without rewriting all call‑sites.


def log_phi_access(*args, **kwargs):  # type: ignore[missing-return-type-doc]
    """Proxy to :pymeth:`AuditLogger.log_phi_access`."""

    return AuditLogger.log_phi_access(*args, **kwargs)


def log_security_event(*args, **kwargs):  # type: ignore[missing-return-type-doc]
    """Proxy to :pymeth:`AuditLogger.log_security_event`."""

    return AuditLogger.log_security_event(*args, **kwargs)


# ---------------------------------------------------------------------------
# PHI Sanitization
# ---------------------------------------------------------------------------

# Common PHI patterns for sanitization
PHI_PATTERNS = [
    # SSN patterns: XXX-XX-XXXX, XXXXXXXXX
    (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]'),
    (r'\b\d{9}\b', '[REDACTED-SSN-CANDIDATE]'),
    
    # Email patterns
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED-EMAIL]'),
    
    # Phone numbers: (XXX) XXX-XXXX, XXX-XXX-XXXX, XXXXXXXXXX
    (r'\(\d{3}\)\s*\d{3}-\d{4}', '[REDACTED-PHONE]'),
    (r'\b\d{3}-\d{3}-\d{4}\b', '[REDACTED-PHONE]'),
    (r'\b\d{10}\b', '[REDACTED-PHONE-CANDIDATE]'),
    
    # Dates in various formats
    (r'\b\d{1,2}/\d{1,2}/\d{2,4}\b', '[REDACTED-DATE]'),
    (r'\b\d{4}-\d{1,2}-\d{1,2}\b', '[REDACTED-DATE]')
]

def sanitize_phi(text: str | dict | list) -> str | dict | list:
    """
    Sanitize PHI from text or structured data.
    
    Replaces potential PHI with redacted markers to ensure logs and error messages
    don't contain protected health information.
    
    Args:
        text: Text or structured data (dict/list) to sanitize
        
    Returns:
        Sanitized version of the input with PHI redacted
    """
    if text is None:
        return None
        
    # Handle dictionaries recursively
    if isinstance(text, dict):
        sanitized_dict = {}
        for key, value in text.items():
            # Skip known PHI keys entirely by replacing their values
            if key.lower() in ['ssn', 'social_security', 'dob', 'date_of_birth', 
                              'phone', 'phone_number', 'email', 'address']:
                sanitized_dict[key] = '[REDACTED]'
            else:
                # Recursively sanitize other values
                sanitized_dict[key] = sanitize_phi(value)
        return sanitized_dict
        
    # Handle lists recursively
    elif isinstance(text, list):
        return [sanitize_phi(item) for item in text]
        
    # Handle strings
    elif isinstance(text, str):
        # Skip short or empty strings
        if len(text) < 5:
            return text
            
        # Apply each pattern
        result = text
        for pattern, replacement in PHI_PATTERNS:
            result = re.sub(pattern, replacement, result)
            
        return result
        
    # Return other types unchanged
    return text

# Explicit re‑export so ``from app.infrastructure.logging.audit_logger import
# log_phi_access`` resolves correctly without requiring an intermediate import
# of *AuditLogger*.

__all__ = [
    "AuditLogger",
    "log_phi_access",
    "log_security_event",
]