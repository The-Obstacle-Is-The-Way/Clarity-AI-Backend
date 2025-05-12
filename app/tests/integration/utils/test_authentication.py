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

from app.core.domain.entities.user import User, UserStatus, UserRole

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
                
                # Map string roles to UserRole enum values
                role_mapping = {
                    "clinician": UserRole.CLINICIAN,
                    "admin": UserRole.ADMIN,
                    "patient": UserRole.PATIENT,
                    "researcher": UserRole.RESEARCHER,
                    "provider": UserRole.CLINICIAN,  # Map provider to clinician for compatibility
                }
                
                # Convert the role string to UserRole
                user_role = role_mapping.get(role_value.lower())
                if not user_role:
                    logger.error(f"TestAuthMiddleware: Invalid role value: {role_value}")
                    return JSONResponse(
                        {"detail": f"Invalid test authentication role: {role_value}. Valid roles are: {list(role_mapping.keys())}"},
                        status_code=HTTP_401_UNAUTHORIZED
                    )
                
                # Create token payload
                token_payload = {
                    "sub": f"test.{role_value}@clarity.health",
                    "id": "00000000-0000-0000-0000-000000000002",
                    "roles": [user_role.value],
                    "exp": int(time.time()) + 3600
                }
                
                # Get user model directly from test data
                user = User(
                    id=token_payload["id"],
                    username="test_provider",
                    email=token_payload["sub"],
                    full_name="Test Provider",
                    password_hash="$2b$12$FakePasswordHashForTestUse..",
                    roles={user_role},
                    account_status=UserStatus.ACTIVE,
                )
                
                # Attach user and credentials to the request
                request.scope["user"] = user
                request.scope["auth"] = AuthCredentials(["authenticated"])
                logger.debug(f"TestAuthMiddleware: Authenticated test user with role: {user_role}")
                
            except Exception as e:
                logger.error(f"TestAuthMiddleware: Authentication error: {str(e)}")
                return JSONResponse(
                    {"detail": f"Invalid test authentication: {str(e)}"},
                    status_code=HTTP_401_UNAUTHORIZED
                )
        else:
            # For paths that aren't public but don't have the header, set unauthenticated
            if not await self._is_public_path(request.url.path):
                return JSONResponse(
                    {"detail": "Not authenticated"},
                    status_code=HTTP_401_UNAUTHORIZED
                )
            # For public paths, attach unauthenticated user
            logger.debug(f"TestAuthMiddleware: Public path accessed: {request.url.path}")
            request.scope["user"] = None  # No user for public paths
            request.scope["auth"] = AuthCredentials([])
        
        # Continue with the request pipeline
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


def create_test_headers_for_role(role: str) -> dict[str, str]:
    """
    Create a set of test request headers that will be recognized by TestAuthenticationMiddleware.
    
    This provides a clean way to create authentication headers for tests without
    dealing with actual JWTs. The role should match one of the supported roles in
    the TestAuthenticationMiddleware.
    
    Args:
        role: Role for the test user (e.g., "CLINICIAN", "ADMIN", "PATIENT")
            This will be normalized to lowercase.
    
    Returns:
        dict: Headers to add to test requests
    """
    normalized_role = role.lower()
    
    # Map role to a consistent format
    role_mapping = {
        "clinician": "clinician",
        "admin": "admin", 
        "patient": "patient",
        "researcher": "researcher",
        "provider": "clinician",  # Map provider to clinician for compatibility
    }
    
    mapped_role = role_mapping.get(normalized_role, normalized_role)
    
    return {
        "X-Test-Auth-Bypass": mapped_role,
        "Authorization": f"Bearer test_{mapped_role}_token"
    }
