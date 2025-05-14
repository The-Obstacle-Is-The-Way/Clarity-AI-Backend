"""
Dependencies for audit logging.

This module provides dependency functions for FastAPI to inject audit logging services.
"""

from fastapi import Depends
from app.core.interfaces.repositories.audit_log_repository_interface import IAuditLogRepository
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.application.services.audit_log_service import AuditLogService
from app.infrastructure.persistence.repositories.audit_log_repository import SQLAlchemyAuditLogRepository
from .repository import get_repository

def get_audit_log_repository() -> IAuditLogRepository:
    """
    Get the audit log repository instance.
    
    Returns:
        IAuditLogRepository: Audit log repository implementation
    """
    return get_repository(SQLAlchemyAuditLogRepository)

def get_audit_log_service(
    repository: IAuditLogRepository = Depends(get_audit_log_repository)
) -> IAuditLogger:
    """
    Get the audit log service instance.
    
    Args:
        repository: Audit log repository for storing logs
        
    Returns:
        IAuditLogger: Audit logger service implementation
    """
    return AuditLogService(repository) 