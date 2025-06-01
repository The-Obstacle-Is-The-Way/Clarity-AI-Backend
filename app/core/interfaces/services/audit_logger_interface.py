"""
Audit logger interface definition.

This module defines the interface for audit logging services, ensuring proper
abstraction between the application layer and concrete infrastructure implementations.
Follows the Interface Segregation Principle (ISP) from SOLID.
"""
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any
from uuid import UUID


class AuditEventType(str, Enum):
    """Types of audit events that can be logged."""
    
    # Authentication events
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_LOCKED = "account_locked"
    
    # Authorization events
    ACCESS_DENIED = "access_denied"
    ACCESS_GRANTED = "access_granted"
    PERMISSION_CHANGED = "permission_changed"
    
    # PHI access events
    PHI_ACCESS = "phi_access"
    PHI_EXPORT = "phi_export"
    PHI_MODIFICATION = "phi_modification"
    
    # Token events
    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_VALIDATED = "token_validated"
    TOKEN_VALIDATION_FAILED = "token_validation_failed"
    TOKEN_REVOCATION = "token_revocation"
    
    # Data events
    DATA_CREATED = "data_created"
    DATA_READ = "data_read"
    DATA_UPDATED = "data_updated"
    DATA_DELETED = "data_deleted"
    
    # System events
    SYSTEM_ERROR = "system_error"
    SYSTEM_WARNING = "system_warning"
    API_CALL = "api_call"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""
    
    CRITICAL = "critical"  # Severe events requiring immediate attention
    HIGH = "high"          # High priority events requiring attention soon
    ERROR = "error"        # Error conditions
    WARNING = "warning"    # Warning conditions
    INFO = "info"          # Informational messages
    DEBUG = "debug"        # Debug-level messages
    TRACE = "trace"        # Detailed trace information


class IAuditLogger(ABC):
    """
    Interface for audit logging services.
    
    All audit logging implementations must adhere to this interface.
    This follows the Dependency Inversion Principle by allowing high-level modules
    to depend on this abstraction rather than concrete implementations.
    """
    
    @abstractmethod
    async def log_phi_access(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: str,
        action: str,
        details: dict[str, Any] | None = None
    ) -> None:
        """
        Log access to PHI (Protected Health Information).
        
        Args:
            user_id: ID of the user accessing PHI
            resource_type: Type of resource being accessed (e.g., "patient", "medical_record")
            resource_id: ID of the resource being accessed
            action: Action being performed (e.g., "read", "update")
            details: Additional details about the access
        """
        pass
    
    @abstractmethod
    async def log_authentication(
        self,
        user_id: UUID | None,
        status: str,
        ip_address: str,
        user_agent: str,
        details: dict[str, Any] | None = None
    ) -> None:
        """
        Log authentication events (successful or failed).
        
        Args:
            user_id: ID of the user if authentication was successful, None otherwise
            status: Status of the authentication (e.g., "success", "failed")
            ip_address: IP address of the client
            user_agent: User agent of the client
            details: Additional details about the authentication event
        """
        pass
    
    @abstractmethod
    async def log_authorization(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: str | None,
        action: str,
        status: str,
        details: dict[str, Any] | None = None
    ) -> None:
        """
        Log authorization events.
        
        Args:
            user_id: ID of the user
            resource_type: Type of resource being accessed
            resource_id: ID of the resource being accessed, if applicable
            action: Action being attempted (e.g., "read", "update")
            status: Status of the authorization (e.g., "granted", "denied")
            details: Additional details about the authorization event
        """
        pass
    
    @abstractmethod
    async def log_error(
        self,
        error_id: str,
        error_type: str,
        original_message: str,
        sanitized_message: str,
        status_code: int,
        request_path: str,
        request_method: str,
        details: dict[str, Any] | None = None
    ) -> None:
        """
        Log error events with special handling for PHI sanitization.
        
        Args:
            error_id: Unique identifier for the error
            error_type: Type of error
            original_message: Original unsanitized error message
            sanitized_message: Sanitized message safe for client response
            status_code: HTTP status code associated with the error
            request_path: Path of the request that triggered the error
            request_method: HTTP method of the request
            details: Additional details about the error
        """
        pass
    
    @abstractmethod
    async def log_operation(
        self,
        user_id: UUID,
        operation_type: str,
        resource_type: str,
        resource_id: str | None,
        status: str,
        details: dict[str, Any] | None = None
    ) -> None:
        """
        Log general operations.
        
        Args:
            user_id: ID of the user performing the operation
            operation_type: Type of operation (e.g., "create", "delete")
            resource_type: Type of resource being operated on
            resource_id: ID of the resource being operated on, if applicable
            status: Status of the operation (e.g., "success", "failed")
            details: Additional details about the operation
        """
        pass
        
    @abstractmethod
    def log_security_event(
        self,
        event_type: AuditEventType,
        user_id: str,
        description: str,
        severity: AuditSeverity,
        metadata: dict[str, Any] | None = None
    ) -> None:
        """
        Log security-related events.
        
        Args:
            event_type: Type of security event from AuditEventType enum
            user_id: ID of the user associated with the event
            description: Human-readable description of the event
            severity: Severity level from AuditSeverity enum
            metadata: Additional details about the security event
        """
        pass