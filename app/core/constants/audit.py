"""
Audit Constants Module

This module defines constants and enumerations related to audit logging
to ensure consistent categories and severity levels across the application.
These constants are used by the audit logger interface and implementations.
"""

from enum import Enum


class AuditSeverity(str, Enum):
    """
    Severity levels for audit events, following industry standards.
    
    These levels align with common logging severity levels but are
    specifically tailored for security and compliance events.
    """
    CRITICAL = "CRITICAL"  # Severe events requiring immediate attention
    ERROR = "ERROR"        # Error conditions
    WARNING = "WARNING"    # Warning conditions
    INFO = "INFO"          # Informational messages
    DEBUG = "DEBUG"        # Debug-level messages


class AuditEventType(str, Enum):
    """
    Types of audit events for categorization and filtering.
    
    These event types provide a consistent taxonomy for security 
    and compliance events across the application.
    """
    # Authentication and access control events
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PASSWORD_RESET = "PASSWORD_RESET"
    MFA_ENABLED = "MFA_ENABLED"
    MFA_DISABLED = "MFA_DISABLED"
    MFA_CHALLENGE = "MFA_CHALLENGE"
    
    # Authorization events
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    ROLE_CHANGE = "ROLE_CHANGE"
    
    # PHI access and modification events
    PHI_ACCESS = "PHI_ACCESS"
    PHI_CREATED = "PHI_CREATED"
    PHI_MODIFIED = "PHI_MODIFIED"
    PHI_DELETED = "PHI_DELETED"
    PHI_EXPORTED = "PHI_EXPORTED"
    
    # Token and session events
    TOKEN_ISSUED = "TOKEN_ISSUED"
    TOKEN_VALIDATED = "TOKEN_VALIDATED"
    TOKEN_REJECTED = "TOKEN_REJECTED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_TERMINATED = "SESSION_TERMINATED"
    
    # User management events
    USER_CREATED = "USER_CREATED"
    USER_MODIFIED = "USER_MODIFIED"
    USER_DELETED = "USER_DELETED"
    USER_LOCKED = "USER_LOCKED"
    USER_UNLOCKED = "USER_UNLOCKED"
    USER_ENABLED = "USER_ENABLED"
    USER_DISABLED = "USER_DISABLED"
    
    # System events
    SYSTEM_STARTUP = "SYSTEM_STARTUP"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    MAINTENANCE_MODE = "MAINTENANCE_MODE"
    ERROR_CONDITION = "ERROR_CONDITION"
    
    # Security events
    SECURITY_ALERT = "SECURITY_ALERT"
    SECURITY_BREACH = "SECURITY_BREACH"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    BRUTE_FORCE_ATTEMPT = "BRUTE_FORCE_ATTEMPT"
    
    # API and request events
    API_REQUEST = "API_REQUEST"
    API_RESPONSE = "API_RESPONSE"
    API_ERROR = "API_ERROR"
    
    # Data operations events
    DATA_IMPORT = "DATA_IMPORT"
    DATA_EXPORT = "DATA_EXPORT"
    DATA_PURGE = "DATA_PURGE"
    DATA_BACKUP = "DATA_BACKUP"
    DATA_RESTORE = "DATA_RESTORE"
    
    # Consent and privacy events
    CONSENT_GRANTED = "CONSENT_GRANTED"
    CONSENT_REVOKED = "CONSENT_REVOKED"
    PRIVACY_POLICY_ACCEPTED = "PRIVACY_POLICY_ACCEPTED"
    DATA_SHARING_ENABLED = "DATA_SHARING_ENABLED"
    DATA_SHARING_DISABLED = "DATA_SHARING_DISABLED"
    
    # Integration events
    EXTERNAL_ACCESS = "EXTERNAL_ACCESS"
    EXTERNAL_SYSTEM_CONNECTED = "EXTERNAL_SYSTEM_CONNECTED"
    EXTERNAL_SYSTEM_DISCONNECTED = "EXTERNAL_SYSTEM_DISCONNECTED"
    
    # Other
    OTHER = "OTHER"  # For events that don't fit other categories
