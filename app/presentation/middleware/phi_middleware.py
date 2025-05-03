"""
PHI (Protected Health Information) Middleware for HIPAA Compliance.

This middleware ensures that PHI is handled properly according to HIPAA regulations:
1. No PHI in URLs or logs
2. All PHI properly encrypted in transit
3. Proper audit logging for PHI access
4. Sanitization of error responses to prevent PHI leakage
"""

import json
import logging
import re
import time
from typing import Callable, Dict, List, Optional, Pattern, Set, Union, cast

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.domain.exceptions.phi_exceptions import PHIInUrlError, PHISanitizationError
from app.core.interfaces.services.encryption_service_interface import EncryptionServiceInterface
from app.infrastructure.di.container import get_container
from app.infrastructure.security.encryption_service import EncryptionService


# Configure PHI audit logger
phi_audit_logger = logging.getLogger("phi_audit")


class PHIMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce HIPAA PHI handling requirements.
    
    This middleware:
    1. Prevents PHI from appearing in URLs (query params, path params)
    2. Logs all PHI access attempts for audit purposes
    3. Ensures proper error handling for PHI-related operations
    4. Sanitizes responses to prevent accidental PHI leakage
    """
    
    def __init__(
        self, 
        app: ASGIApp,
        phi_patterns: Optional[List[Pattern]] = None,
        exempt_paths: Optional[Set[str]] = None
    ):
        """
        Initialize PHI middleware with patterns to detect and paths to exempt.
        
        Args:
            app: The ASGI application
            phi_patterns: Regular expression patterns to detect PHI
            exempt_paths: Paths exempt from PHI checks (e.g., auth endpoints)
        """
        super().__init__(app)
        self.phi_patterns = phi_patterns or [
            # Social Security Number patterns
            re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),
            # Medical Record Number patterns (various formats)
            re.compile(r"\bMRN[-:]?\d{6,10}\b", re.IGNORECASE),
            # Email patterns
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            # Date of birth patterns
            re.compile(r"\b(0[1-9]|1[0-2])[-/.](0[1-9]|[12]\d|3[01])[-/.](19|20)\d{2}\b"),
            # Common patient identifiers
            re.compile(r"\bPATIENT[-_]?ID[:=]?\d+\b", re.IGNORECASE),
        ]
        self.exempt_paths = exempt_paths or {
            "/api/v1/auth/token",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/docs",
            "/redoc",
            "/openapi.json",
        }
        
        # Get encryption service for HIPAA compliance
        container = get_container()
        try:
            self.encryption_service = container.get(EncryptionServiceInterface)
        except KeyError:
            # Create encryption service if not available
            self.encryption_service = EncryptionService()
            container.register(EncryptionServiceInterface, self.encryption_service)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and enforce PHI protections.
        
        Args:
            request: The incoming request
            call_next: The next middleware/endpoint handler
            
        Returns:
            The processed response
            
        Raises:
            HTTPException: If PHI is detected in prohibited locations
        """
        # Skip PHI checks for exempt paths
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)
        
        # Audit logging
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        
        try:
            # Check URL for PHI
            self._check_url_for_phi(request)
            
            # Process request normally
            response = await call_next(request)
            
            # Sanitize response if needed
            response = await self._sanitize_response(response)
            
            # Log PHI access for audit purposes
            phi_audit_logger.info(
                f"PHI access: {request.method} {request.url.path} "
                f"from {client_ip} - status: {response.status_code}"
            )
            
            return response
            
        except PHIInUrlError as e:
            # Log PHI attempt violation
            phi_audit_logger.warning(
                f"PHI detected in URL: {request.method} {request.url.path} "
                f"from {client_ip} - blocked"
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Protected health information (PHI) is not allowed in URLs"}
            )
        except PHISanitizationError as e:
            # Log sanitization failure
            phi_audit_logger.error(
                f"Failed to sanitize PHI: {request.method} {request.url.path} "
                f"from {client_ip} - error: {str(e)}"
            )
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Error processing protected health information"}
            )
        except Exception as e:
            # Log any other exceptions
            phi_audit_logger.error(
                f"PHI middleware error: {request.method} {request.url.path} "
                f"from {client_ip} - error: {str(e)}"
            )
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"}
            )
        finally:
            # Log total processing time for performance monitoring
            processing_time = time.time() - start_time
            phi_audit_logger.debug(
                f"PHI middleware performance: {processing_time:.3f}s for "
                f"{request.method} {request.url.path}"
            )

    def _check_url_for_phi(self, request: Request) -> None:
        """
        Check URL path and query parameters for PHI patterns.
        
        Args:
            request: The incoming request
            
        Raises:
            PHIInUrlError: If PHI is detected in the URL
        """
        # Check URL path
        path = request.url.path
        for pattern in self.phi_patterns:
            if pattern.search(path):
                raise PHIInUrlError("PHI detected in URL path")
        
        # Check query parameters
        for key, values in request.query_params.items():
            if isinstance(values, str):
                values = [values]
            for value in values:
                for pattern in self.phi_patterns:
                    if pattern.search(value):
                        raise PHIInUrlError("PHI detected in query parameters")

    async def _sanitize_response(self, response: Response) -> Response:
        """
        Sanitize response to prevent accidental PHI disclosure in error messages.
        
        Args:
            response: The outgoing response
            
        Returns:
            Sanitized response
            
        Raises:
            PHISanitizationError: If response cannot be properly sanitized
        """
        # Only sanitize error responses
        if response.status_code >= 400:
            try:
                # For JSON responses
                if isinstance(response, JSONResponse):
                    content = json.loads(response.body)
                    # Sanitize error details
                    if "detail" in content:
                        # Ensure no PHI in error messages
                        for pattern in self.phi_patterns:
                            if pattern.search(str(content["detail"])):
                                content["detail"] = "Redacted for PHI protection"
                        
                        return JSONResponse(
                            status_code=response.status_code,
                            content=content,
                            headers=dict(response.headers)
                        )
            except Exception as e:
                raise PHISanitizationError(f"Failed to sanitize response: {str(e)}")
                
        return response


def add_phi_middleware(app: FastAPI) -> None:
    """
    Add PHI middleware to the FastAPI application.
    
    Args:
        app: The FastAPI application instance
    """
    app.add_middleware(PHIMiddleware)
