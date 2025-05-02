"""
Test Authentication Utilities

This module provides utilities for setting up and managing authentication
in test environments, including direct authentication bypasses for integration testing.
"""

import logging
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_401_UNAUTHORIZED

logger = logging.getLogger(__name__)

class TestAuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Test-specific middleware for authentication.
    
    This middleware intercepts authentication checks and allows passing preauthorized users
    in test environments. This creates a clean separation between test and production code
    and follows clean architecture principles.
    """
    
    def __init__(
        self,
        app: FastAPI,
        public_paths: list[str] | set[str] | None = None,
        auth_bypass_header: str = "X-Test-Auth-Bypass",
    ):
        """
        Initialize the test authentication middleware.
        
        Args:
            app: FastAPI application instance
            public_paths: Paths that don't require authentication
            auth_bypass_header: Header name for passing test auth info
        """
        super().__init__(app)
        self.public_paths = set(public_paths or [])
        self.auth_bypass_header = auth_bypass_header
        
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Process each request through the middleware.
        
        Args:
            request: The incoming request
            call_next: The next middleware or route handler
            
        Returns:
            Response object
        """
        # Skip authentication for public paths
        if self._is_public_path(request.url.path):
            return await call_next(request)
        
        # Look for test auth bypass header
        auth_info = request.headers.get(self.auth_bypass_header)
        if auth_info:
            try:
                # Parse role from header (format: "ROLE:USER_ID")
                role, user_id = auth_info.split(":", 1)
                
                # Create a dictionary representation of user for compatibility with both User model and dict access
                user_dict = {
                    "id": user_id,
                    "sub": user_id,  # Required for JWT compatibility
                    "username": f"test_{role.lower()}",
                    "email": f"test.{role.lower()}@novamind.ai",
                    "role": role.upper(),
                    "roles": [role.upper()],
                    "is_active": True,
                    "is_verified": True,
                    "permissions": ["predict_risk", "predict_treatment", "predict_outcome"]
                }
                
                # Attach to request state
                request.state.user = user_dict
                return await call_next(request)
                
            except Exception as e:
                logger.warning(f"Test auth bypass failed: {e}")
                return self._create_error_response(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Invalid test authentication bypass"
                )
        
        # Standard auth processing (will be handled by route dependencies)
        return await call_next(request)
    
    def _is_public_path(self, path: str) -> bool:
        """Check if a path is in the public paths list."""
        return path in self.public_paths
    
    def _create_error_response(self, status_code: int, detail: str) -> Response:
        """Create a JSON error response."""
        return Response(
            content=f'{{"detail":"{detail}"}}',
            status_code=status_code,
            media_type="application/json"
        )


def create_test_headers_for_role(role: str, user_id: str = None) -> dict[str, str]:
    """
    Create test headers that will bypass authentication in test environment.
    
    Args:
        role: User role (e.g., "PATIENT", "CLINICIAN")
        user_id: Optional user ID, defaults to standard test IDs if not provided
        
    Returns:
        Dict with headers for test authentication bypass
    """
    if user_id is None:
        # Default test user IDs
        if role.upper() == "PATIENT":
            user_id = "00000000-0000-0000-0000-000000000001"
        elif role.upper() in ("CLINICIAN", "PROVIDER"):
            user_id = "00000000-0000-0000-0000-000000000002"
        elif role.upper() == "ADMIN":
            user_id = "00000000-0000-0000-0000-000000000003"
    
    return {
        "X-Test-Auth-Bypass": f"{role.upper()}:{user_id}",
        "Content-Type": "application/json"
    }
