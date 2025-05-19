"""
Security Headers Middleware for FastAPI applications.

This middleware adds standard security headers to HTTP responses to protect 
against common web vulnerabilities like XSS, clickjacking, and MIME sniffing.
"""


from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.config.settings import get_settings
from app.core.utils.logging import get_logger

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to HTTP responses.

    These headers help protect against common web security vulnerabilities
    and implement security best practices as part of HIPAA compliance.
    """

    def __init__(
        self,
        app: FastAPI,
        csp_policy: str | None = None,
        hsts_max_age: int = 31536000,  # 1 year
        exempt_paths: list[str] | None = None,
    ):
        """
        Initialize the security headers middleware.

        Args:
            app: The FastAPI application
            csp_policy: Custom Content-Security-Policy value
            hsts_max_age: HSTS max-age in seconds
            exempt_paths: Paths exempt from some security headers
        """
        super().__init__(app)
        self.settings = get_settings()
        self.exempt_paths = set(exempt_paths or [])
        self.hsts_max_age = hsts_max_age

        # Default strict CSP policy if none provided
        self.csp_policy = csp_policy or (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-src 'none'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # Define standard security headers to always apply
        self.standard_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
        }

        logger.info("SecurityHeadersMiddleware initialized")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """
        Process the request and add security headers to the response.

        Args:
            request: The incoming HTTP request
            call_next: The next middleware or endpoint to call

        Returns:
            The HTTP response with added security headers
        """
        # Process the request through the middleware chain
        response = await call_next(request)

        # Apply standard security headers to all responses
        for header_name, header_value in self.standard_headers.items():
            response.headers[header_name] = header_value

        # Apply Content-Security-Policy for HTML responses
        content_type = response.headers.get("Content-Type", "")
        if "text/html" in content_type:
            response.headers["Content-Security-Policy"] = self.csp_policy

        # Apply HSTS header only on HTTPS connections (except in local development)
        if self.settings.ENVIRONMENT != "development" and request.url.scheme == "https":
            response.headers[
                "Strict-Transport-Security"
            ] = f"max-age={self.hsts_max_age}; includeSubDomains; preload"

        # Special handling for API responses
        if request.url.path.startswith("/api/"):
            # For API responses, we might want to add additional security headers
            # or modify existing ones for JSON/API specific security
            pass

        return response
