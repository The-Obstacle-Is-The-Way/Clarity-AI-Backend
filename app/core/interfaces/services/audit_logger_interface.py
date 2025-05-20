"""
Interface for Audit Logger classes.

This module defines the interface for audit logging services that record security,
access, and system events for compliance with HIPAA and other regulatory requirements.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from app.core.constants.audit import AuditEventType, AuditSeverity


class IAuditLogger(ABC):
    """
    Interface for audit logging services.
    
    Implementations of this interface should handle the logging of security,
    access, and system events in a manner that complies with HIPAA and other
    regulatory requirements.
    """

    @abstractmethod
    def log_security_event(
        self, 
        event_type: str,
        description: str,
        user_id: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log a security-related event.
        
        Args:
            event_type: Type of security event (e.g., "LOGIN_SUCCESS", "ACCESS_DENIED")
            description: Human-readable description of the event
            user_id: ID of the user associated with the event (if applicable)
            severity: Severity level of the event
            metadata: Additional contextual information about the event
        """
        pass
    
    @abstractmethod
    def log_phi_access(
        self,
        actor_id: str,
        patient_id: str,
        data_accessed: str,
        access_reason: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log access to Protected Health Information (PHI).
        
        Args:
            actor_id: ID of the user or system accessing the PHI
            patient_id: ID of the patient whose PHI was accessed
            data_accessed: Description of the PHI data that was accessed
            access_reason: Reason for accessing the PHI
            metadata: Additional contextual information about the access
        """
        pass
    
    @abstractmethod
    def log_auth_event(
        self,
        event_type: str,
        user_id: str,
        success: bool,
        description: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an authentication or authorization event.
        
        Args:
            event_type: Type of auth event (e.g., "LOGIN", "LOGOUT", "TOKEN_VALIDATION")
            user_id: ID of the user associated with the event
            success: Whether the auth operation succeeded
            description: Human-readable description of the event
            metadata: Additional contextual information about the event
        """
        pass
    
    @abstractmethod
    def log_system_event(
        self,
        event_type: str,
        description: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log a system-level event.
        
        Args:
            event_type: Type of system event (e.g., "STARTUP", "SHUTDOWN", "ERROR")
            description: Human-readable description of the event
            severity: Severity level of the event
            metadata: Additional contextual information about the event
        """
        pass