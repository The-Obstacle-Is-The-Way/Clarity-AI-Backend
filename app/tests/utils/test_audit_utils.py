"""
Utility functions for working with audit logs in tests.

This module provides utility functions to help with testing code that uses
audit logging, allowing it to be disabled or mocked during tests.
"""

from typing import AsyncGenerator, Optional, Union
from fastapi import FastAPI
from contextlib import asynccontextmanager

from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.infrastructure.persistence.repositories.mock_audit_log_repository import MockAuditLogRepository
from app.application.services.audit_log_service import AuditLogService


def disable_audit_middleware(app: FastAPI) -> None:
    """
    Disable the audit middleware for testing purposes.
    
    Args:
        app: The FastAPI application instance
    """
    app.state.disable_audit_middleware = True


def enable_audit_middleware(app: FastAPI) -> None:
    """
    Enable the audit middleware if it was previously disabled.
    
    Args:
        app: The FastAPI application instance
    """
    app.state.disable_audit_middleware = False


def get_mock_audit_service() -> IAuditLogger:
    """
    Create a mock audit service for testing.
    
    Returns:
        IAuditLogger: A mock audit service implementation
    """
    mock_repo = MockAuditLogRepository()
    return AuditLogService(mock_repo)


@asynccontextmanager
async def disable_audit_logging(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Context manager to temporarily disable audit logging during a test.
    
    Args:
        app: The FastAPI application instance
        
    Yields:
        None
    """
    # Store previous state
    previous_state = getattr(app.state, "disable_audit_middleware", False)
    
    # Disable audit middleware
    app.state.disable_audit_middleware = True
    
    try:
        yield
    finally:
        # Restore previous state
        app.state.disable_audit_middleware = previous_state 