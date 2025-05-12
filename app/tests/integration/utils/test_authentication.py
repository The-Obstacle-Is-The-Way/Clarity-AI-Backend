"""
Test Authentication Utilities

This module provides utilities for setting up and managing authentication
in test environments, including direct authentication bypasses for integration testing.
"""

import logging
from collections.abc import Awaitable, Callable
import time

import pytest
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_401_UNAUTHORIZED
from starlette.responses import JSONResponse
from starlette.authentication import AuthCredentials

from app.core.domain.entities.user import User, UserStatus

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
        logger.info(f"Test Authentication Middleware initialized with bypass header: {auth_bypass_header}")
        
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Process authentication for test routes.
        
        This middleware allows test requests to bypass normal security checks
        when using test-specific headers.
        
        Args:
            request: FastAPI request object
            call_next: Next middleware/handler
            
        Returns:
            Response after processing auth
        """
        # Check if request has test bypass header 
        if self.auth_bypass_header in request.headers:
            # Get and decode the test user data
            try:
                role_value = request.headers.get(self.auth_bypass_header, "clinician")
                token_payload = {
                    "id": "00000000-0000-0000-0000-000000000002",  # Test clinician ID
                    "sub": "test.provider@novamind.ai",
                    "roles": [role_value, "provider"],  # Always include provider role for these tests
                    "iss": "https://test.auth.novamind.ai/",
                    "exp": int(time.time()) + 3600  # Token valid for 1 hour
                }
                
                # Get user model directly from test data
                user = User(
                    id=token_payload["id"],
                    username="test_provider",
                    email=token_payload["sub"],
                    full_name="Test Provider",
                    password_hash="$2b$12$FakePasswordHashForTestUse..",
                    roles=set(token_payload["roles"]),
                    account_status=UserStatus.ACTIVE,
                )
                
                # Set authentication in request scope
                request.scope["user"] = user
                request.scope["auth"] = AuthCredentials(["authenticated"] + token_payload["roles"])
                
                # For debugging
                logger.debug(f"TestAuthMiddleware: Added test auth for route {request.url.path}, user {user.id}")
                return await call_next(request)
                
            except (ValueError, KeyError) as e:
                logger.error(f"TestAuthMiddleware: Invalid test token format: {str(e)}")
                return JSONResponse(
                    status_code=HTTP_401_UNAUTHORIZED,
                    content={"detail": f"Invalid test authentication: {str(e)}"}
                )
                
        # Proceed normally if no test bypass header
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
