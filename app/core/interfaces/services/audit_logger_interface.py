"""
Audit Logger Interface.

This module defines the interface for audit logging services in compliance with HIPAA requirements.
Following the Interface Segregation Principle from SOLID and Clean Architecture patterns,
this interface decouples the audit logging contract from its implementations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, Optional, Union


class AuditEventType(str, Enum):
    """Types of auditable events in the system."""
    
    # Authentication events
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    
    # Authorization events
    ACCESS_DENIED = "access_denied"
    PERMISSION_CHANGED = "permission_changed"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    
    # Data access events
    PHI_ACCESSED = "phi_accessed"
    PHI_MODIFIED = "phi_modified"
    PHI_DELETED = "phi_deleted"
    PHI_EXPORTED = "phi_exported"
    
    # System events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIGURATION_CHANGED = "configuration_changed"
    
    # User management
    USER_CREATED = "user_created"
    USER_MODIFIED = "user_modified"
    USER_DEACTIVATED = "user_deactivated"
    
    # API events
    API_REQUEST = "api_request"
    API_RESPONSE = "api_response"
    
    # ML model events
    MODEL_INFERENCE = "model_inference"
    MODEL_TRAINED = "model_trained"
    MODEL_DEPLOYED = "model_deployed"
    
    # Fallback for other events
    OTHER = "other"


class AuditSeverity(str, Enum):
    """Severity level of audit events."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IAuditLogger(ABC):
    """Interface for audit logging services.
    
    This interface defines the contract that all audit logging implementations
    must fulfill to ensure HIPAA compliance and proper security tracking.
    """
    
    @abstractmethod
    async def log_event(
        self,
        event_type: AuditEventType,
        actor_id: Optional[str] = None,
        target_resource: Optional[str] = None,
        target_id: Optional[str] = None,
        action: Optional[str] = None,
        status: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ) -> str:
        """Log an audit event in the system.
        
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
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        pass
    
    @abstractmethod
    async def log_security_event(
        self,
        description: str,
        actor_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.HIGH,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log a security-related event.
        
        Convenience method for security events like authentication failures.
        
        Args:
            description: Description of the security event
            actor_id: ID of the user/system involved
            status: Status of the security event
            severity: Severity level of the event
            details: Additional details about the event
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        pass
    
    @abstractmethod
    async def log_phi_access(
        self,
        actor_id: str,
        patient_id: str,
        resource_type: str,
        action: str,
        status: str,
        phi_fields: Optional[list[str]] = None,
        reason: Optional[str] = None,
    ) -> str:
        """Log PHI access event specifically.
        
        Specialized method for PHI access to ensure proper HIPAA audit trails.
        
        Args:
            actor_id: ID of the user accessing PHI
            patient_id: ID of the patient whose PHI was accessed
            resource_type: Type of resource containing PHI (e.g., "medical_record")
            action: Action performed on PHI (e.g., "view", "modify")
            status: Outcome of the access attempt
            phi_fields: Specific PHI fields accessed (without values)
            reason: Business reason for accessing the PHI
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        pass
    
    @abstractmethod
    async def get_audit_trail(
        self,
        filters: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Dict[str, Any]]:
        """Retrieve audit trail entries based on filters.
        
        Args:
            filters: Optional filters to apply (e.g., event_type, actor_id)
            start_time: Optional start time for the audit trail
            end_time: Optional end time for the audit trail
            limit: Maximum number of entries to return
            offset: Offset for pagination
            
        Returns:
            list[Dict[str, Any]]: List of audit log entries matching the criteria
        """
        pass
