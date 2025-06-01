"""
Dependency providers for logging services.

This module provides FastAPI dependency injection functions for logging-related services,
ensuring proper adherence to Clean Architecture principles by exposing interfaces
rather than concrete implementations to dependent components.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.infrastructure.logging.audit_logger import AuditLogger


def get_audit_logger() -> IAuditLogger:
    """
    Dependency provider for AuditLogger service.
    
    Returns an implementation of IAuditLogger interface to ensure
    proper dependency inversion according to Clean Architecture principles.
    
    Returns:
        An implementation of IAuditLogger.
    """
    # Return the concrete implementation, but as the interface type
    # to ensure proper dependency inversion
    return AuditLogger()


# Type hint for dependency injection using the interface
AuditLoggerDep = Annotated[IAuditLogger, Depends(get_audit_logger)]


__all__ = [
    "get_audit_logger",
    "AuditLoggerDep",
]
