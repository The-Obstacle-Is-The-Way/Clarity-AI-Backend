"""
Authentication middleware for FastAPI applications.

This middleware extracts and validates JWT tokens from requests,
and attaches the authenticated user to the request state.
It implements HIPAA-compliant logging and authorization checks.
"""

import re
import logging
from typing import List, Optional, Set, Callable, Dict, Any, Union
from fastapi import Request, Response, FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN
)

from app.domain.exceptions import (
    AuthenticationError, 
    InvalidTokenError,
    TokenExpiredError, 
    MissingTokenError,
    PermissionDeniedError
)
from app.domain.entities.user import User
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.core.config.settings import Settings, settings  
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts and validates JWT tokens from the request headers.
    It also handles authentication-related errors and public path access.
    """
    
    def __init__(
        self, 
        app: FastAPI,
        auth_service: AuthenticationService,
        jwt_service: JWTService,
        settings: Settings = None,
        public_paths: Optional[Union[List[str], Set[str]]] = None,
        public_path_regex: Optional[List[str]] = None,
    ):
        """
        Initialize the authentication middleware.
        
        Args:
            app: FastAPI application
            auth_service: Authentication service
            jwt_service: JWT service
            settings: Application settings
            public_paths: List or set of paths that don't require authentication
            public_path_regex: List of regex patterns for paths that don't require authentication
        """
        super().__init__(app)
        self.auth_service = auth_service
        self.jwt_service = jwt_service
        # Use global settings if none provided
        self.settings = settings or Settings()
        
        # Initialize public paths - convert to list if it's a set
        self.public_paths: List[str] = list(public_paths) if public_paths else []
        
        # Add default public paths
        default_public_paths = [
            "/",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/metrics",
            "/api/auth/login",
            "/api/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/register",
        ]
        
        # Add default paths that aren't already in public_paths
        for path in default_public_paths:
            if path not in self.public_paths:
                self.public_paths.append(path)
        
        # Compile regex patterns for faster matching
        self.public_path_patterns: List[re.Pattern] = []
        if public_path_regex:
            for pattern in public_path_regex:
                try:
                    self.public_path_patterns.append(re.compile(pattern))
                except re.error as e:
                    logger.warning(f"Invalid regex pattern for public path: {pattern}, error: {e}")
                
        # Ensure all public paths start with "/"
        for i, path in enumerate(self.public_paths):
            if not path.startswith("/"):
                self.public_paths[i] = f"/{path}"
                
        logger.info(f"AuthenticationMiddleware initialized with {len(self.public_paths)} public paths")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request, extract and validate JWT token, and attach user to request state.
        
        Args:
            request: The incoming request
            call_next: The next middleware to call
            
        Returns:
            The response from the route handler
        """
        # Log request (without PHI) for audit trail
        path = request.url.path
        method = request.method
        client_host = request.client.host if request.client else "unknown"
        logger.debug(f"Request: {method} {path} from {client_host}")
        
        # Skip authentication for public paths
        if await self._is_public_path(path):
            logger.debug(f"Skipping authentication for public path: {path}")
            return await call_next(request)
            
        try:
            # Extract token from Authorization header
            token = await self._extract_token(request)
            if not token:
                raise MissingTokenError("Authentication token is missing")
                
            # Validate token and get user
            user, permissions = await self.auth_service.validate_token(token)
            
            # Attach user and permissions to request state
            request.state.user = user
            request.state.permissions = permissions
            request.state.token = token  # Store token for potential use in handlers
            
            # Process the request
            response = await call_next(request)
            return response
            
        except MissingTokenError as e:
            # Authentication required but token is missing
            logger.warning(f"Authentication failed: {str(e)}")
            return self._create_error_response(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                error_code="AUTHENTICATION_REQUIRED"
            )
            
        except TokenExpiredError as e:
            # Token has expired
            logger.info(f"Authentication failed: Token expired for request to {path}")
            return self._create_error_response(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired",
                error_code="TOKEN_EXPIRED"
            )
            
        except InvalidTokenError as e:
            # Token is invalid
            logger.warning(f"Authentication failed: Invalid token for request to {path}")
            return self._create_error_response(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                error_code="INVALID_TOKEN"
            )
            
        except AuthenticationError as e:
            # General authentication error
            logger.warning(f"Authentication failed: {str(e)}")
            return self._create_error_response(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                error_code="AUTHENTICATION_FAILED"
            )
            
        except PermissionDeniedError as e:
            # User doesn't have necessary permissions
            logger.warning(f"Permission denied: {str(e)}")
            return self._create_error_response(
                status_code=HTTP_403_FORBIDDEN,
                detail="Permission denied",
                error_code="PERMISSION_DENIED"
            )
            
        except Exception as e:
            # Unexpected error
            logger.error(f"Unexpected error during authentication: {str(e)}", exc_info=True)
            return self._create_error_response(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Authentication failed due to an unexpected error",
                error_code="AUTHENTICATION_ERROR"
            )

    async def _is_public_path(self, path: str) -> bool:
        """
        Check if the path is public (doesn't require authentication).
        
        Args:
            path: The request path
            
        Returns:
            True if the path is public, False otherwise
        """
        # Check exact path matches
        if path in self.public_paths:
            return True
            
        # Check OpenAPI paths
        if path in ["/docs", "/redoc", "/openapi.json"] or path.startswith("/static/"):
            return True
            
        # Check regex patterns
        for pattern in self.public_path_patterns:
            if pattern.match(path):
                return True
                
        return False

    async def _extract_token(self, request: Request) -> Optional[str]:
        """
        Extract the JWT token from the Authorization header.
        
        Args:
            request: The incoming request
            
        Returns:
            The JWT token if found, None otherwise
        """
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None
            
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
            
        token = parts[1]
        return token

    def _create_error_response(
        self, 
        status_code: int, 
        detail: str, 
        error_code: str
    ) -> JSONResponse:
        """
        Create a standardized error response.
        
        Args:
            status_code: HTTP status code
            detail: Error detail message
            error_code: Error code for client reference
            
        Returns:
            JSONResponse with error details
        """
        content = {
            "status": "error",
            "code": error_code,
            "message": detail,
        }
        
        response = JSONResponse(
            status_code=status_code,
            content=content
        )
        
        # Add WWW-Authenticate header for 401 responses
        if status_code == HTTP_401_UNAUTHORIZED:
            response.headers["WWW-Authenticate"] = f'Bearer realm="{self.settings.API_TITLE}", error="{error_code}"'
            
        return response
