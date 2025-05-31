"""
Security headers implementation for API protection.

This module provides middleware for adding security-related HTTP headers
to responses, helping to protect against common web vulnerabilities.
"""

import logging
from collections.abc import Callable
from typing import Callable, Awaitable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware for adding security headers to HTTP responses.

    This middleware adds HTTP security headers to responses to improve
    security against XSS, clickjacking, and other web vulnerabilities.
    """

    def __init__(self, app, security_headers: dict[str, str] | None = None):
        """
        Initialize the security headers middleware.

        Args:
            app: The FastAPI application
            security_headers: Optional dictionary of security headers to use instead of defaults
        """
        super().__init__(app)
        # Default security headers used for all responses if not overridden
        self.default_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
        }

        # If custom headers are provided, use those instead
        self.headers = security_headers if security_headers is not None else self.default_headers

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Process the request and add security headers to the response.

        Args:
            request: The incoming HTTP request
            call_next: The next middleware/endpoint in the chain

        Returns:
            The HTTP response with added security headers
        """
        # Get response from downstream handlers
        response: Response = await call_next(request)

        # Add security headers to response
        for header_name, header_value in self.headers.items():
            response.headers[header_name] = header_value

        return response
