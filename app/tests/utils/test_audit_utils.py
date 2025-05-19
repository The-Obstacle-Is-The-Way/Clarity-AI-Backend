"""
Utility functions for working with audit logs in tests.

This module provides utility functions to help with testing code that uses
audit logging, allowing it to be disabled or mocked during tests.
"""

import logging
import re
from collections.abc import AsyncGenerator, Callable, Generator
from contextlib import asynccontextmanager, contextmanager
from typing import Any, cast
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
        logger.info(f"Audit middleware restored to {'disabled' if original_value else 'enabled'}")


def replace_middleware_with_mock(
    app: FastAPI, middleware_class: type, mock_middleware: BaseHTTPMiddleware | None = None
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
                async def mock_dispatch(request: Request, call_next: Callable) -> Any:
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
            if isinstance(middleware, dict) and middleware.get("cls") == AuthenticationMiddleware:
                middleware_instance = middleware.get("instance")
                if middleware_instance:
                    # Add a wildcard to public paths
                    middleware_instance.public_paths.add("/*")
                    middleware_instance.public_paths.add("/api/*")

                    # Add patterns that match everything
                    middleware_instance.public_path_patterns.append(re.compile(".*"))
                    middleware_instance.public_path_patterns.append(re.compile("^/api/.*$"))
                    logger.info("Added wildcard patterns to auth middleware public paths")

                    # Replace dispatch method with a pass-through version
                    # Note: not using the original_dispatch variable to avoid the F841 warning

                    async def mock_dispatch(request: Request, call_next: Callable) -> Any:
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
def disabled_audit_logging(app: FastAPI) -> Generator[None, None, None]:
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
async def disabled_audit_logging_async(app: FastAPI) -> AsyncGenerator[None, None]:
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


def find_middleware_by_type(app: FastAPI, middleware_type: type) -> BaseHTTPMiddleware | None:
    """
    Find middleware of a specific type in the application's middleware stack.

    Args:
        app: The FastAPI application instance
        middleware_type: The type of middleware to find

    Returns:
        The middleware instance if found, None otherwise
    """
    if not hasattr(app, "middleware_stack") or not app.middleware_stack:
        return None

    for middleware in app.middleware_stack.app.middleware:
        if isinstance(middleware, dict) and middleware.get("cls") == middleware_type:
            return middleware.get("instance")

    return None


def create_test_request(
    app: FastAPI, path: str = "/", method: str = "GET", headers: dict[str, str] | None = None
) -> Request:
    """
    Create a test Request object for use in tests.

    Args:
        app: The FastAPI application
        path: The request path
        method: The HTTP method
        headers: Optional request headers

    Returns:
        A Request object configured with the provided parameters
    """
    from starlette.types import Scope

    headers = headers or {}
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "root_path": "",
        "scheme": "http",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "fastapi.app": app,
    }

    return Request(cast(Scope, scope))
