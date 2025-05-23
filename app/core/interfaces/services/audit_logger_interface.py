"""
Interface for audit logging services to maintain a clean architecture boundary between
layers and ensure HIPAA compliance for security logging.

This interface defines the contract that all audit logging implementations must follow,
allowing the application layer to depend on abstractions rather than concrete implementations.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any


class AuditEventType(str, Enum):
    """Standardized audit event types for consistent logging across the application."""

    # Authentication events
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"  # Added for test compatibility
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PASSWORD_RESET = "PASSWORD_RESET"

    # Token events
    TOKEN_CREATION = "TOKEN_CREATION"
    TOKEN_VALIDATION = "TOKEN_VALIDATION"
    TOKEN_VALIDATION_FAILED = "TOKEN_VALIDATION_FAILED"
    TOKEN_REFRESH = "TOKEN_REFRESH"
    TOKEN_REVOCATION = "TOKEN_REVOCATION"

    # Access control events
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"

    # Data events
    DATA_ACCESS = "DATA_ACCESS"
    PHI_ACCESS = "PHI_ACCESS"  # Added for HIPAA logging
    DATA_MODIFICATION = "DATA_MODIFICATION"
    DATA_DELETION = "DATA_DELETION"
    DATA_EXPORT = "DATA_EXPORT"

    # Security events
    SECURITY_ALERT = "SECURITY_ALERT"  # Added for security anomaly detection

    # System events
    SYSTEM_STARTUP = "SYSTEM_STARTUP"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    ERROR = "ERROR"
    WARNING = "WARNING"


class AuditSeverity(str, Enum):
    """Standardized severity levels for audit events."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"  # Added for backward compatibility


class IAuditLogger(ABC):
    """Interface for HIPAA-compliant audit logging services.

    This interface ensures all audit logging implementations provide consistent
    methods for recording security events, errors, and other audit information
    while maintaining separation of concerns in the clean architecture.
    """

    @abstractmethod
    def log_security_event(
        self,
        event_type: AuditEventType,
        description: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        user_id: str | None = None,
        metadata: dict[str, Any] | None = None,
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
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
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
        user_id: str | None = None,
        request_id: str | None = None,
        duration_ms: float | None = None,
        metadata: dict[str, Any] | None = None,
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
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log system-level events for operational auditing.

        Args:
            event_type: Type of system event
            description: Human-readable description of the event
            severity: Severity level (INFO, WARNING, ERROR)
            metadata: Additional contextual information about the event
        """
        pass
