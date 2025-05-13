"""
HIPAA-compliant audit logging service for PHI access and security events.

This module provides a comprehensive audit logging mechanism for Protected Health 
Information (PHI) access and security events, ensuring compliance with HIPAA audit
requirements (45 CFR § 164.312(b) and 45 CFR § 164.308(a)(1)(ii)(D)).
"""

import logging
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List, Union

# Get a dedicated logger for audit events
_audit_log = logging.getLogger("audit")

class AuditLogger:
    """
    HIPAA-compliant audit logging service for tracking PHI access and security events.
    
    This class provides methods to log and track:
    - PHI access (who accessed what PHI and when)
    - Security events (authentication, authorization, etc.)
    - System events (configuration changes, etc.)
    """
    
    def log_access(
        self,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        field_name: Optional[str] = None,
        action: str = "view",
        user_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
        severity: str = "info"
    ) -> str:
        """
        Log access to protected health information (PHI) for HIPAA compliance.
        
        Args:
            resource_id: ID of the resource being accessed (e.g., patient ID)
            resource_type: Type of resource (e.g., "Patient", "MedicalRecord")
            field_name: Specific field being accessed
            action: Action being performed (view, update, delete)
            user_id: ID of the user performing the access
            additional_data: Any additional data to include in the log
            severity: Log severity level
            
        Returns:
            The ID of the audit log entry
        """
        # Generate a unique ID for this log entry
        log_id = str(uuid.uuid4())
        
        # Construct the log entry
        log_entry = {
            "log_id": log_id,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "phi_access",
            "resource_id": resource_id,
            "resource_type": resource_type,
            "field_name": field_name,
            "action": action,
            "user_id": user_id,
            "additional_data": additional_data or {}
        }
        
        # Log the event at the appropriate level
        log_method = getattr(_audit_log, severity.lower(), _audit_log.info)
        log_method(f"PHI Access: {action} {resource_type}:{resource_id} field:{field_name}", extra=log_entry)
        
        return log_id
    
    def log_security_event(
        self,
        event_type: str,
        event_details: Dict[str, Any],
        user_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        severity: str = "info"
    ) -> str:
        """
        Log a security-related event such as authentication, authorization, etc.
        
        Args:
            event_type: Type of security event (auth, access_control, etc.)
            event_details: Details of the event
            user_id: ID of the user associated with the event
            resource_id: ID of any resource involved
            severity: Log severity level
            
        Returns:
            The ID of the audit log entry
        """
        # Generate a unique ID for this log entry
        log_id = str(uuid.uuid4())
        
        # Construct the log entry
        log_entry = {
            "log_id": log_id,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "event_details": event_details,
            "user_id": user_id,
            "resource_id": resource_id
        }
        
        # Log the event at the appropriate level
        log_method = getattr(_audit_log, severity.lower(), _audit_log.info)
        log_method(f"Security Event: {event_type}", extra=log_entry)
        
        return log_id
    
    def log_system_event(
        self,
        event_type: str,
        event_details: Dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info"
    ) -> str:
        """
        Log a system-level event such as configuration changes.
        
        Args:
            event_type: Type of system event
            event_details: Details of the event
            user_id: ID of the user who triggered the event
            severity: Log severity level
            
        Returns:
            The ID of the audit log entry
        """
        # Generate a unique ID for this log entry
        log_id = str(uuid.uuid4())
        
        # Construct the log entry
        log_entry = {
            "log_id": log_id,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "event_details": event_details,
            "user_id": user_id
        }
        
        # Log the event at the appropriate level
        log_method = getattr(_audit_log, severity.lower(), _audit_log.info)
        log_method(f"System Event: {event_type}", extra=log_entry)
        
        return log_id

# Create a singleton instance
audit_logger = AuditLogger() 