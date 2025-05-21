"""
Audit logger dependency provider.

This module provides the dependency injection for audit logger services
used throughout the application for HIPAA-compliant security event logging.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.infrastructure.logging.audit_logger import AuditLogger


def get_audit_logger():
    """
    Provides an audit logger implementation.
    
    Creates and returns an instance of the audit logger for security event tracking.
    
    Returns:
        An implementation of the IAuditLogger interface
    """
    return AuditLogger()


# Type annotation for dependency injection
# Use concrete implementation for FastAPI compatibility while preserving
# clean architecture inside the application
from app.infrastructure.logging.audit_logger import AuditLogger
AuditLoggerDep = Annotated[AuditLogger, Depends(get_audit_logger)]
