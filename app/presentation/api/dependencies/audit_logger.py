"""
Audit logger dependency provider.

This module provides the dependency injection for audit logger services
used throughout the application for HIPAA-compliant security event logging.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.infrastructure.logging.audit_logger import AuditLogger


def get_audit_logger() -> IAuditLogger:
    """
    Provides an audit logger implementation.

    Creates and returns an instance of the audit logger for security event tracking.

    Returns:
        An implementation of the IAuditLogger interface
    """
    return AuditLogger()


# Type annotation for dependency injection
# Use the interface type for dependency injection to ensure proper
# dependency inversion principle according to Clean Architecture
AuditLoggerDep = Annotated[IAuditLogger, Depends(get_audit_logger)]


__all__ = [
    "AuditLoggerDep",
    "get_audit_logger",
]
