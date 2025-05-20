"""
Interface for Audit Logger classes.

This module defines the interface for audit logging services that record security,
access, and system events for compliance with HIPAA and other regulatory requirements.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, List, Awaitable

from app.core.constants.audit import AuditEventType, AuditSeverity

# Export these constants for use by implementations
__all__ = ['IAuditLogger', 'AuditEventType', 'AuditSeverity']


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
        description: str = None,
        user_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: Optional[str] = None,
        status: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
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
        pass
    
    @abstractmethod
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
        metadata: Optional[Dict[str, Any]] = None
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
        pass
    
    @abstractmethod
    def log_auth_event(
        self,
        event_type: str,
        user_id: str,
        success: bool,
        description: str,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an authentication or authorization event.
        
        Args:
            event_type: Type of auth event (e.g., "LOGIN", "LOGOUT", "TOKEN_VALIDATION")
            user_id: ID of the user associated with the event
            success: Whether the auth operation succeeded
            description: Human-readable description of the event
            ip_address: IP address of the actor
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
        
    @abstractmethod
    def get_audit_trail(
        self,
        user_id: Optional[str] = None,
        patient_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: Optional[int] = 100,
        offset: Optional[int] = 0
    ) -> List[Dict[str, Any]]:
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
        pass