"""
Interface for audit logging services to maintain a clean architecture boundary between
layers and ensure HIPAA compliance for security logging.

This interface defines the contract that all audit logging implementations must follow,
allowing the application layer to depend on abstractions rather than concrete implementations.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class IAuditLogger(ABC):
    """Interface for HIPAA-compliant audit logging services.
    
    This interface ensures all audit logging implementations provide consistent
    methods for recording security events, errors, and other audit information
    while maintaining separation of concerns in the clean architecture.
    """
    
    @abstractmethod
    def log_security_event(
        self, 
        event_type: str,
        description: str,
        severity: str = "INFO",
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log a security-related event for audit purposes.
        
        Args:
            event_type: Type of security event (e.g., LOGIN, LOGOUT, TOKEN_ISSUED)
            description: Human-readable description of the event
            severity: Severity level (INFO, WARNING, ERROR)
            user_id: Optional user identifier associated with the event
            metadata: Additional contextual information about the event
        """
        pass
    
    @abstractmethod
    def log_data_access(
        self,
        resource_type: str,
        resource_id: str,
        action: str,
        user_id: str,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log access to sensitive data for HIPAA compliance.
        
        Args:
            resource_type: Type of resource being accessed (e.g., PATIENT, RECORD)
            resource_id: Identifier of the resource
            action: Action performed (e.g., VIEW, EDIT, DELETE)
            user_id: User who performed the action
            reason: Optional reason for access
            metadata: Additional contextual information about the access
        """
        pass
    
    @abstractmethod
    def log_api_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        duration_ms: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log API request information for audit trails.
        
        Args:
            endpoint: API endpoint that was accessed
            method: HTTP method used (GET, POST, etc.)
            status_code: HTTP status code of the response
            user_id: Optional user identifier who made the request
            request_id: Optional unique identifier for the request
            duration_ms: Optional request duration in milliseconds
            metadata: Additional contextual information about the request
        """
        pass
    
    @abstractmethod
    def log_system_event(
        self,
        event_type: str,
        description: str,
        severity: str = "INFO",
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log system-level events for operational auditing.
        
        Args:
            event_type: Type of system event
            description: Human-readable description of the event
            severity: Severity level (INFO, WARNING, ERROR)
            metadata: Additional contextual information about the event
        """
        pass