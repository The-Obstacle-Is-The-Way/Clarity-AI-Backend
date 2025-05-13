"""
HIPAA-compliant audit logging utility.

This module provides a centralized way to access the audit logger
for HIPAA-compliant tracking of PHI access and modifications.
"""

from typing import Any, Optional

from app.infrastructure.security.audit_logger import AuditLogger

_audit_logger = None

def get_audit_logger() -> AuditLogger:
    """
    Get the singleton audit logger instance.
    
    Returns:
        AuditLogger: The application's audit logger
    """
    global _audit_logger
    
    if _audit_logger is None:
        _audit_logger = AuditLogger()
        
    return _audit_logger 