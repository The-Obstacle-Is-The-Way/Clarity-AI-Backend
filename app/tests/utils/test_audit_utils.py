"""
Utility functions for working with audit logs in tests.

This module provides utility functions to help with testing code that uses
audit logging, allowing it to be disabled or mocked during tests.
"""

from typing import AsyncGenerator, Optional, Union, Callable
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager, contextmanager
from starlette.middleware.base import BaseHTTPMiddleware
import logging
from unittest.mock import AsyncMock, MagicMock

from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.infrastructure.persistence.repositories.mock_audit_log_repository import MockAuditLogRepository
from app.application.services.audit_log_service import AuditLogService
from app.infrastructure.security.audit.middleware import AuditLogMiddleware

logger = logging.getLogger(__name__)

def disable_audit_middleware(app: FastAPI) -> None:
    """
    Disable the audit middleware for testing purposes.
    
    Args:
        app: The FastAPI application instance
    """
    app.state.disable_audit_middleware = True
    logger.debug(f"Explicitly disabled audit middleware for app: {id(app)}")


def enable_audit_middleware(app: FastAPI) -> None:
    """
    Enable the audit middleware if it was previously disabled.
    
    Args:
        app: The FastAPI application instance
    """
    app.state.disable_audit_middleware = False


def get_mock_audit_service() -> IAuditLogger:
    """
    Get a mock audit service for testing.
    
    Returns:
        IAuditLogger: A mock audit service that doesn't use the database
    """
    repository = MockAuditLogRepository()
    return AuditLogService(repository)


@contextmanager
def disabled_audit_logging(app: FastAPI):
    """
    Context manager to temporarily disable audit logging.
    
    Args:
        app: The FastAPI application instance
    """
    # Save the original state
    original_state = getattr(app.state, "disable_audit_middleware", False)
    
    # Disable audit logging
    app.state.disable_audit_middleware = True
    
    try:
        # Yield control back to the caller
        yield
    finally:
        # Restore the original state
        app.state.disable_audit_middleware = original_state


@asynccontextmanager
async def disabled_audit_logging_async(app: FastAPI):
    """
    Async context manager to temporarily disable audit logging.
    
    Args:
        app: The FastAPI application instance
    """
    # Save the original state
    original_state = getattr(app.state, "disable_audit_middleware", False)
    
    # Disable audit logging
    app.state.disable_audit_middleware = True
    
    try:
        # Yield control back to the caller
        yield
    finally:
        # Restore the original state
        app.state.disable_audit_middleware = original_state


def find_middleware_by_type(app: FastAPI, middleware_type: type) -> Optional[BaseHTTPMiddleware]:
    """
    Find middleware of a specific type in the application.
    
    Args:
        app: The FastAPI application instance
        middleware_type: The type of middleware to find
        
    Returns:
        Optional[BaseHTTPMiddleware]: The middleware instance if found, None otherwise
    """
    for middleware in app.user_middleware:
        cls = middleware.cls
        if cls == middleware_type or issubclass(cls, middleware_type):
            return middleware
    return None


def replace_middleware_with_mock(app: FastAPI, middleware_type: type, mock_middleware: Optional[Callable] = None) -> None:
    """
    Replace middleware of a specific type with a mock implementation.
    
    Args:
        app: The FastAPI application instance
        middleware_type: The type of middleware to replace
        mock_middleware: Optional mock middleware to use instead
    """
    # Find the middleware
    for i, middleware in enumerate(app.user_middleware):
        cls = middleware.cls
        if cls == middleware_type or issubclass(cls, middleware_type):
            # Remove the middleware
            app.user_middleware.pop(i)
            
            # Add mock middleware if provided
            if mock_middleware:
                app.add_middleware(mock_middleware)
                
            # Only replace the first occurrence
            break

class MockAuditLogMiddleware(BaseHTTPMiddleware):
    """Mock implementation of AuditLogMiddleware for testing."""
    
    def __init__(self, app):
        """Initialize with mocked methods."""
        super().__init__(app)
        self.dispatch = AsyncMock()
        self.dispatch.return_value = None
        
    async def dispatch(self, request: Request, call_next: Callable):
        """Mock dispatch implementation that just passes through."""
        return await call_next(request)

def create_test_request(app: FastAPI, path: str = "/", method: str = "GET", headers: dict = None) -> Request:
    """
    Create a mock Request object for testing.
    
    Args:
        app: The FastAPI application
        path: URL path
        method: HTTP method
        headers: Request headers
        
    Returns:
        Request: A mock Request object
    """
    # Create minimal scope for request
    scope = {
        "type": "http",
        "app": app,
        "path": path,
        "method": method,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("127.0.0.1", 8000),
        "path_params": {},
        "query_string": b"",
        "url": f"http://testserver{path}",
        "session": {}
    }
    
    # Create request
    request = Request(scope)
    
    # Set disable flag directly on request.state
    setattr(request.state, "disable_audit_middleware", True)
    
    # Copy app state values to request state
    if hasattr(app.state, "settings"):
        setattr(request.state, "settings", app.state.settings)
    
    if hasattr(app.state, "jwt_service"):
        setattr(request.state, "jwt_service", app.state.jwt_service)
    
    # Add mock user if needed
    setattr(request.state, "user", MagicMock(id="test_user_id"))
    
    return request 