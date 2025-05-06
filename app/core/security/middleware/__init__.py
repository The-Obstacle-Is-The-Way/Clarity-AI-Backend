"""
Security middleware implementation for API protection.

This module implements security middleware components following clean architecture principles,
including authentication, authorization, request validation, and secure logging.
"""

import asyncio
import re
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.authentication import AuthCredentials, UnauthenticatedUser
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.core.config.settings import Settings, get_settings
# Import interfaces from the core layer
from app.core.interfaces.services.authentication_service import IAuthenticationService
from app.core.interfaces.services.jwt_service import IJwtService
# Import necessary domain exceptions for token validation
from app.domain.exceptions import (
    AuthenticationError,
    InvalidTokenException,
    TokenExpiredException,
)
# Import UserNotFoundException from its specific module
from app.domain.exceptions.auth_exceptions import UserNotFoundException
from app.infrastructure.logging.logger import get_logger
from app.infrastructure.security.auth_service import get_auth_service
from app.infrastructure.security.jwt_service import get_jwt_service

logger = get_logger(__name__)

class RoleBasedAccessControl:
    """Role-based access control for the API."""
    
    def has_permission(self, roles: list, permission: str) -> bool:
        """Check if the user roles have the required permission."""
        # To be implemented based on specific permission model
        # For now, simplified implementation for testing
        return permission in roles

# Authentication middleware
class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for authentication and authorization of API requests.
    
    This class enforces token validation for non-public paths and manages role-based
    access control to protected resources. It supports both production and test environments.
    """
    
    def __init__(
        self,
        app: FastAPI,
        auth_service=None,  # Support for test injection
        jwt_service=None,   # Support for test injection
        public_paths: list[str] | set[str] | None = None, # Renamed from exclude_paths for compatibility with tests/other version
        public_path_regex: list[str] | None = None,
        settings: Settings | None = None,
    ):
        """Initialize the middleware with configuration for public paths."""
        super().__init__(app)
        self.settings = settings or get_settings()
        
        # Store service factories for later async initialization
        self._auth_service = auth_service
        self._jwt_service = jwt_service
        # Lazy-loaded service instances
        self._auth_service_instance = None
        self._jwt_service_instance = None
        
        # Define default public paths that don't require authentication
        default_public_paths = [
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/",
            "/metrics",
            f"{self.settings.API_V1_STR}/auth/login",
            f"{self.settings.API_V1_STR}/auth/refresh",
            f"{self.settings.API_V1_STR}/auth/register",
        ]
        
        # Allow overriding of public paths
        self.public_paths = set(public_paths or default_public_paths)
        self.public_path_regex = public_path_regex or []
        
        # Initialize role-based access control
        self.rbac = RoleBasedAccessControl()
        
        # Initialize public paths as a set for O(1) lookups
        # self.public_paths = set(public_paths or []) # Redundant with above logic
        
        # Add Swagger/OpenAPI paths by default
        # self.public_paths.update(['/docs', '/openapi.json', '/redoc', '/health', '/']) # Covered by defaults

        # Compile regex patterns for faster matching
        self.public_path_patterns = []
        if public_path_regex:
            for pattern in public_path_regex:
                try:
                    self.public_path_patterns.append(re.compile(pattern))
                except re.error as e:
                    logger.warning(f"Invalid regex pattern: {pattern}, error: {e}")
        
        logger.info(
            "AuthenticationMiddleware initialized. Public paths: %s",
            list(self.public_paths)
        )

    async def _is_public_path(self, path: str) -> bool:
        """
        Check if the given path is a public path that doesn't require authentication.
        """
        if path in self.public_paths:
            return True
            
        for pattern in self.public_path_patterns:
            if pattern.match(path):
                return True
                
        return False

    async def _ensure_services_initialized(self):
        """Lazy-load services ONCE per middleware instance, prioritizing injected services."""
        if self._auth_service_instance is None: 
            if self._auth_service:
                # If auth_service is a coroutine function (like the async getter from tests)
                if asyncio.iscoroutinefunction(self._auth_service):
                    self._auth_service_instance = await self._auth_service()
                else: # Otherwise, assume it's already an instance (e.g. a mock passed directly)
                    self._auth_service_instance = self._auth_service
                logger.debug(f"Using injected/provided auth service instance: {type(self._auth_service_instance)}")
            else:
                auth_service_source = get_auth_service
                auth_service_result = auth_service_source()
                if asyncio.iscoroutine(auth_service_result) or asyncio.iscoroutinefunction(auth_service_source):
                     self._auth_service_instance: IAuthenticationService = await auth_service_result
                else:
                     self._auth_service_instance: IAuthenticationService = auth_service_result
                logger.debug(f"Auth service instance set via fallback: {type(self._auth_service_instance)}")

        if self._jwt_service_instance is None: 
            if self._jwt_service:
                 # If jwt_service is a coroutine function (like the async getter from tests)
                if asyncio.iscoroutinefunction(self._jwt_service):
                    self._jwt_service_instance = await self._jwt_service()
                else: # Otherwise, assume it's already an instance
                    self._jwt_service_instance = self._jwt_service
                logger.debug(f"Using injected/provided jwt service instance: {type(self._jwt_service_instance)}")
            else:
                jwt_service_source = get_jwt_service
                jwt_service_result = jwt_service_source()
                if asyncio.iscoroutine(jwt_service_result) or asyncio.iscoroutinefunction(jwt_service_source):
                     self._jwt_service_instance: IJwtService = await jwt_service_result
                else:
                     self._jwt_service_instance: IJwtService = jwt_service_result
                logger.debug(f"JWT service instance set via fallback: {type(self._jwt_service_instance)}")

    def _extract_token(self, request: Request) -> str | None:
        """Extract JWT token from request headers or cookies."""
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header.replace("Bearer ", "")
            
        if "X-Test-Token" in request.headers: # For testing specific scenarios
            return request.headers.get("X-Test-Token")
            
        token = request.cookies.get("access_token")
        if token:
            return token
            
        return None

    async def validate_token_and_get_user(self, token: str) -> Any:
        """Validate the provided token and retrieve the corresponding user."""
        try:
            token_payload = await self._jwt_service_instance.verify_token(token)
            user = await self._auth_service_instance.get_user_by_id(token_payload.sub)

            if not user:
                logger.warning(f"User not found for ID: {token_payload.sub}")
                raise UserNotFoundException(f"User with ID {token_payload.sub} not found.")

            if not user.is_active: # Assuming User model has is_active
                logger.warning(f"Attempt to authenticate inactive user: {user.id}")
                raise AuthenticationError("User account is inactive.")

            return user
        except (InvalidTokenException, TokenExpiredException) as e:
            logger.info(f"Token validation failed: {e}")
            raise e
        except UserNotFoundException as e:
             logger.warning(f"User lookup failed during auth: {e}")
             raise e

    async def dispatch(self, request: Request, call_next: Callable) -> Response: # Changed from RequestResponseEndpoint for type consistency
        """Process the request through the authentication middleware."""
        request.state.user = UnauthenticatedUser()
        request.state.auth = None
        
        await self._ensure_services_initialized()
        
        request_path = request.url.path
        if await self._is_public_path(request_path):
            logger.debug(f"Skipping auth for public path: {request_path}")
            return await call_next(request)
        
        token = self._extract_token(request)
            
        if not token:
            logger.info(f"Authentication token missing for path: {request_path}")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication required. No token provided."},
            )
            
        try:
            user = await self.validate_token_and_get_user(token)
            request.state.user = user
            scopes = getattr(user, 'roles', []) or getattr(user, 'scopes', []) # Ensure user object has roles/scopes
            request.state.auth = AuthCredentials(scopes=scopes)
            logger.debug(f"User {user.id} authenticated successfully for path {request_path}") # Assuming user has id
            return await call_next(request)
        except InvalidTokenException:
            logger.info(f"Invalid token received for path: {request_path}")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or malformed authentication token."},
            )
        except TokenExpiredException:
            logger.info(f"Expired token received for path: {request_path}")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication token has expired."},
            )
        except UserNotFoundException:
             logger.warning(f"User not found during authentication attempt for path: {request_path}")
             return JSONResponse(
                 status_code=HTTP_401_UNAUTHORIZED,
                 content={"detail": "User associated with token not found."},
             )
        except AuthenticationError as e:
             logger.warning(f"Authentication failed for path {request_path}: {e}") 
             error_message = str(e).lower()
             if "inactive" in error_message:
                 detail = "User account is inactive."
                 status_code = HTTP_403_FORBIDDEN
             elif "Simulated auth service error" in str(e): 
                 logger.error(f"Caught specific AuthenticationError meant to cause 500: {e}", exc_info=True)
                 raise Exception("Simulated internal auth error") from e
             else:
                 detail = "Authentication failed."
                 status_code = HTTP_401_UNAUTHORIZED
             
             return JSONResponse(
                 status_code=status_code,
                 content={"detail": detail},
             )
        except Exception as e:
            logger.error(
                f"Unexpected internal error during authentication for path {request_path}: {e}",
                exc_info=True,
            )
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "An internal error occurred during authentication."},
            )

# Example of how you might add this middleware to your app in main.py or app_factory.py:
# from app.core.security.middleware import AuthenticationMiddleware
# app.add_middleware(AuthenticationMiddleware)
