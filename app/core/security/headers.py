"""
Security headers implementation for API protection.

This module provides middleware for adding security-related HTTP headers
to responses, helping to protect against common web vulnerabilities.
"""

import logging
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware for adding security headers to HTTP responses.
    
    This middleware adds HTTP security headers to responses to improve
    security against XSS, clickjacking, and other web vulnerabilities.
    """
    
    def __init__(self, app):
        """
        Initialize the security headers middleware.
        
        Args:
            app: The FastAPI application
        """
        super().__init__(app)
        # Default security headers used for all responses
        self.default_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache"
        }
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and add security headers to the response.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware/endpoint in the chain
            
        Returns:
            The HTTP response with added security headers
        """
        # Get response from downstream handlers
        response = await call_next(request)
        
        # Add security headers to response
        for header_name, header_value in self.default_headers.items():
            response.headers[header_name] = header_value
            
        return response
