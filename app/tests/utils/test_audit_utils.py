"""
Utility functions for working with audit logs in tests.

This module provides utility functions to help with testing code that uses
audit logging, allowing it to be disabled or mocked during tests.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, contextmanager
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.application.services.audit_log_service import AuditLogService
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.infrastructure.persistence.repositories.mock_audit_log_repository import (
    MockAuditLogRepository,
)

logger = logging.getLogger(__name__)


def disable_audit_middleware(app: FastAPI) -> None:
    """
    Disable audit logging middleware in the application for testing.

    Args:
        app: The FastAPI application instance
    """
    if not hasattr(app, "state"):
        app.state = MagicMock()

    app.state.disable_audit_middleware = True
    logger.info("Audit middleware disabled for testing")


def mock_audit_log_service() -> IAuditLogger:
    """
    Create a mocked audit log service for testing.

    Returns:
        A mocked audit logger service
    """
    mock_repo = MockAuditLogRepository()
    return AuditLogService(repository=mock_repo)


@asynccontextmanager
async def disable_audit_middleware_context(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Context manager to temporarily disable audit middleware.

    Args:
        app: The FastAPI application instance

    Yields:
        None
    """
    original_value = getattr(app.state, "disable_audit_middleware", False)
    app.state.disable_audit_middleware = True
    logger.info("Audit middleware temporarily disabled")

    try:
        yield
    finally:
        app.state.disable_audit_middleware = original_value
        logger.info(
            f"Audit middleware restored to {'disabled' if original_value else 'enabled'}"
        )


def replace_middleware_with_mock(
    app: FastAPI, middleware_class: type, mock_middleware: BaseHTTPMiddleware = None
) -> None:
    """
    Replace a middleware in the application with a mocked version.

    Args:
        app: The FastAPI application instance
        middleware_class: The class of middleware to replace
        mock_middleware: Optional mock middleware to use as replacement
    """
    if not app.middleware_stack:
        logger.warning("No middleware stack found in application")
        return

    # Find the middleware in the stack
    for i, middleware in enumerate(app.middleware_stack.app.middleware):
        if isinstance(middleware, dict) and middleware.get("cls") == middleware_class:
            if mock_middleware:
                app.middleware_stack.app.middleware[i]["instance"] = mock_middleware
            else:
                # Create a pass-through mock middleware
                async def mock_dispatch(request, call_next):
                    return await call_next(request)

                mock = AsyncMock()
                mock.dispatch = mock_dispatch
                app.middleware_stack.app.middleware[i]["instance"] = mock

            logger.info(f"Replaced {middleware_class.__name__} middleware with mock")
            return

    logger.warning(
        f"Middleware {middleware_class.__name__} not found in application middleware stack"
    )


def disable_authentication_middleware(app: FastAPI) -> None:
    """
    Disable authentication middleware in the application for testing.

    Args:
        app: The FastAPI application instance
    """
    from app.presentation.middleware.authentication import AuthenticationMiddleware

    # Set app state flag to disable auth checks
    if not hasattr(app, "state"):
        app.state = MagicMock()

    app.state.disable_auth_middleware = True
    logger.info("Authentication middleware flagged as disabled")

    # Add wildcard to public paths for the middleware
    if hasattr(app, "middleware_stack") and app.middleware_stack:
        for middleware in app.middleware_stack.app.middleware:
            if (
                isinstance(middleware, dict)
                and middleware.get("cls") == AuthenticationMiddleware
            ):
                middleware_instance = middleware.get("instance")
                if middleware_instance:
                    # Add a wildcard to public paths
                    middleware_instance.public_paths.add("/*")
                    middleware_instance.public_paths.add("/api/*")

                    # Add patterns that match everything
                    import re

                    middleware_instance.public_path_patterns.append(re.compile(".*"))
                    middleware_instance.public_path_patterns.append(
                        re.compile("^/api/.*$")
                    )
                    logger.info(
                        "Added wildcard patterns to auth middleware public paths"
                    )

                    # Replace dispatch method with a pass-through version
                    original_dispatch = middleware_instance.dispatch

                    async def mock_dispatch(request, call_next):
                        # Add authentication data directly to request
                        from starlette.authentication import AuthCredentials

                        from app.core.domain.entities.user import UserRole

                        # Create mock authenticated user
                        mock_user = MagicMock()
                        mock_user.is_authenticated = True
                        mock_user.id = "test-user-id-123"
                        mock_user.username = "test_user"
                        mock_user.email = "test@example.com"
                        mock_user.roles = [
                            UserRole.CLINICIAN.value,
                            UserRole.ADMIN.value,
                        ]

                        # Set authentication on request
                        request.scope["auth"] = AuthCredentials(
                            ["authenticated", "clinician", "admin"]
                        )
                        request.scope["user"] = mock_user

                        # Also set on request.state for middleware that checks there
                        if not hasattr(request, "state"):
                            request.state = type("MockState", (), {})()

                        request.state.user = mock_user
                        request.state.authenticated = True

                        return await call_next(request)

                    # Replace the middleware dispatch method
                    middleware_instance.dispatch = mock_dispatch
                    logger.info(
                        "Authentication middleware dispatch method replaced with mock version"
                    )
                    break


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


def find_middleware_by_type(
    app: FastAPI, middleware_type: type
) -> BaseHTTPMiddleware | None:
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


def create_test_request(
    app: FastAPI, path: str = "/", method: str = "GET", headers: dict = None
) -> Request:
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
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
        "client": ("127.0.0.1", 8000),
        "path_params": {},
        "query_string": b"",
        "url": f"http://testserver{path}",
        "session": {},
    }

    # Create request
    request = Request(scope)

    # Set disable flag directly on request.state
    request.state.disable_audit_middleware = True

    # Copy app state values to request state
    if hasattr(app.state, "settings"):
        request.state.settings = app.state.settings

    if hasattr(app.state, "jwt_service"):
        request.state.jwt_service = app.state.jwt_service

    # Add mock user if needed
    request.state.user = MagicMock(id="test_user_id")

    return request
