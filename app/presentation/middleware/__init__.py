"""
Middleware components for the API presentation layer.

This package contains middleware components that handle request/response processing,
including authentication, logging, rate limiting, and other cross-cutting concerns.
All middleware components are HIPAA-compliant by design.
"""

from app.presentation.middleware.authentication import AuthenticationMiddleware
from app.presentation.middleware.logging import LoggingMiddleware

__all__ = ["AuthenticationMiddleware", "LoggingMiddleware"]
