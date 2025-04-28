"""
HIPAA-compliant middleware for PHI protection in API endpoints.

This module provides FastAPI middleware components to protect PHI in
requests and responses, ensuring HIPAA compliance at the API layer.
"""

import time
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Union, Tuple, Set

from fastapi import FastAPI, Request, Response, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .phi_service import PHIService
from .log_sanitizer import LogSanitizer, get_sanitized_logger

# Create a sanitized logger
logger = get_sanitized_logger(__name__)


class PHIMiddleware(BaseHTTPMiddleware):
    """
    Middleware that sanitizes PHI in requests and responses.
    
    This middleware intercepts API requests and responses to:
    1. Sanitize PHI in request bodies for logging purposes
    2. Sanitize PHI in response bodies to prevent inadvertent exposure
    3. Enforce HIPAA-compliant security headers
    4. Audit PHI access and exposure events
    """
    
    def __init__(
        self,
        app: ASGIApp,
        phi_service: Optional[PHIService] = None,
        audit_mode: bool = False,
        exclude_paths: Optional[List[str]] = None,
        whitelist_patterns: Optional[List[str]] = None
    ):
        """
        Initialize PHI middleware.
        
        Args:
            app: The ASGI application
            phi_service: Optional PHIService for PHI detection and sanitization
            audit_mode: Whether to log PHI exposure without sanitizing
            exclude_paths: Optional list of paths to exclude from sanitization
            whitelist_patterns: Optional list of patterns to exclude from sanitization
        """
        super().__init__(app)
        self.phi_service = phi_service or PHIService()
        self.audit_mode = audit_mode
        self.exclude_paths = exclude_paths or []
        self.whitelist_patterns = whitelist_patterns or []
        
        # Default paths to exclude (common API docs and health check paths)
        self.default_exclude_paths = [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/metrics"
        ]
        
        # Add default exclusions
        for path in self.default_exclude_paths:
            if path not in self.exclude_paths:
                self.exclude_paths.append(path)
                
        # Headers to add for HIPAA compliance
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-XSS-Protection": "1; mode=block",
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
            "Pragma": "no-cache"
        }
        
    def is_excluded_path(self, path: str) -> bool:
        """
        Check if a path is excluded from PHI sanitization.
        
        Args:
            path: Request path to check
            
        Returns:
            True if path should be excluded, False otherwise
        """
        return any(path.startswith(excluded) for excluded in self.exclude_paths)
    
    def is_whitelisted(self, text: str) -> bool:
        """
        Check if a string contains whitelisted patterns that should not be sanitized.
        
        Args:
            text: Text to check against whitelist
            
        Returns:
            True if text contains a whitelisted pattern, False otherwise
        """
        if not text or not isinstance(text, str):
            return False
            
        for pattern in self.whitelist_patterns:
            if pattern in text:
                return True
                
        return False
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process an incoming request and sanitize PHI.
        
        Args:
            request: The incoming request
            call_next: Function to call the next middleware/route handler
            
        Returns:
            Sanitized response
        """
        # Skip excluded paths
        if self.is_excluded_path(request.url.path):
            return await call_next(request)
            
        # Process the request with timing for performance monitoring
        start_time = time.time()
        
        # Copy request for potential sanitization (for logging only)
        # Actual request processing uses the original request
        await self._sanitize_request_for_logging(request)
        
        # Process the request normally
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Skip non-JSON responses
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type.lower():
            self._add_security_headers(response)
            return response
            
        # Get response body
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk
            
        # Skip empty responses
        if not response_body:
            self._add_security_headers(response)
            return response
            
        # Process the response body for PHI
        try:
            # Parse the response body as JSON
            body_json = json.loads(response_body)
            
            # Check for PHI in the response
            contains_phi = self._check_for_phi(body_json)
            
            # Sanitize or audit the response
            if contains_phi:
                logger.warning(
                    "PHI detected in API response for %s %s",
                    request.method,
                    request.url.path
                )
                
                if self.audit_mode:
                    # In audit mode, log the finding but don't modify the response
                    logger.info(
                        "Audit mode: PHI would be sanitized in response to %s %s",
                        request.method,
                        request.url.path
                    )
                    sanitized_body = body_json
                else:
                    # Sanitize the response body
                    sanitized_body = self.phi_service.sanitize_dict(body_json)
                    logger.info(
                        "PHI sanitized in response to %s %s",
                        request.method,
                        request.url.path
                    )
            else:
                # No PHI detected, just pass through
                sanitized_body = body_json
                
            # Create a new response with the sanitized body
            response = JSONResponse(
                content=sanitized_body,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
            # Log request handling time
            logger.debug(
                "Processed %s %s in %.3fs",
                request.method,
                request.url.path,
                process_time
            )
            
            # Add security headers
            self._add_security_headers(response)
            
            return response
            
        except json.JSONDecodeError:
            # Not a valid JSON response, return as is
            self._add_security_headers(response)
            return response
        except Exception as e:
            # Log the error and return the original response
            logger.error(
                "Error processing response from %s %s: %s",
                request.method,
                request.url.path,
                str(e)
            )
            self._add_security_headers(response)
            return response
    
    async def _sanitize_request_for_logging(self, request: Request) -> None:
        """
        Create a sanitized copy of the request body for logging.
        
        This doesn't modify the actual request used for processing.
        
        Args:
            request: The request to sanitize
        """
        try:
            # Only sanitize JSON requests
            content_type = request.headers.get("content-type", "")
            if "application/json" not in content_type.lower():
                return
                
            # Read the request body once
            body = await request.body()
            if not body:
                return
                
            # Parse and sanitize for logging purposes
            body_json = json.loads(body)
            
            # Check for PHI
            contains_phi = self._check_for_phi(body_json)
            
            if contains_phi:
                logger.warning(
                    "PHI detected in request to %s %s",
                    request.method,
                    request.url.path
                )
                
                if self.audit_mode:
                    # In audit mode, just log the finding
                    logger.info(
                        "Audit mode: PHI found in request to %s %s",
                        request.method,
                        request.url.path
                    )
                    sanitized_body = body_json
                else:
                    # Sanitize the body for logging
                    sanitized_body = self.phi_service.sanitize_dict(body_json)
                    logger.info(
                        "PHI sanitized in request logging for %s %s",
                        request.method,
                        request.url.path
                    )
                    
                # Store sanitized body for logging if needed
                request.state.sanitized_request_body = sanitized_body
                
        except json.JSONDecodeError:
            # Not JSON, ignore
            pass
        except Exception as e:
            logger.error(
                "Error sanitizing request to %s %s: %s",
                request.method,
                request.url.path,
                str(e)
            )
    
    def _check_for_phi(self, data: Any) -> bool:
        """
        Check if data contains PHI.
        
        Args:
            data: Data to check for PHI (string, dict, list, etc.)
            
        Returns:
            True if data contains PHI, False otherwise
        """
        if data is None:
            return False
            
        if isinstance(data, str):
            # Skip whitelisted patterns
            if self.is_whitelisted(data):
                return False
            return self.phi_service.contains_phi(data)
        elif isinstance(data, dict):
            # Check each value in the dictionary
            for key, value in data.items():
                if self._check_for_phi(value):
                    return True
        elif isinstance(data, (list, tuple)):
            # Check each item in the list
            for item in data:
                if self._check_for_phi(item):
                    return True
                    
        return False
    
    def _add_security_headers(self, response: Response) -> None:
        """
        Add HIPAA-compliant security headers to the response.
        
        Args:
            response: Response to modify
        """
        for name, value in self.security_headers.items():
            response.headers[name] = value


# Dependency for FastAPI routes
def get_phi_middleware(
    phi_service: Optional[PHIService] = None,
    audit_mode: bool = False,
    exclude_paths: Optional[List[str]] = None,
    whitelist_patterns: Optional[List[str]] = None
) -> PHIMiddleware:
    """
    Get a PHI middleware instance for use with FastAPI.
    
    Args:
        phi_service: Optional PHIService for PHI detection and sanitization
        audit_mode: Whether to log PHI exposure without sanitizing
        exclude_paths: Optional list of paths to exclude from sanitization
        whitelist_patterns: Optional list of patterns to exclude from sanitization
        
    Returns:
        PHI middleware instance
    """
    return PHIMiddleware(
        app=None,  # Will be set by FastAPI
        phi_service=phi_service,
        audit_mode=audit_mode,
        exclude_paths=exclude_paths,
        whitelist_patterns=whitelist_patterns
    )


def add_phi_middleware(
    app: FastAPI,
    phi_service: Optional[PHIService] = None,
    audit_mode: bool = False,
    exclude_paths: Optional[List[str]] = None,
    whitelist_patterns: Optional[List[str]] = None
) -> None:
    """
    Add PHI middleware to a FastAPI application.
    
    Args:
        app: FastAPI application instance
        phi_service: Optional PHIService for PHI detection and sanitization
        audit_mode: Whether to log PHI exposure without sanitizing
        exclude_paths: Optional list of paths to exclude from sanitization
        whitelist_patterns: Optional list of patterns to exclude from sanitization
    """
    middleware = PHIMiddleware(
        app=app,
        phi_service=phi_service,
        audit_mode=audit_mode,
        exclude_paths=exclude_paths,
        whitelist_patterns=whitelist_patterns
    )
    
    app.add_middleware(BaseHTTPMiddleware, dispatch=middleware.dispatch)
    
    logger.info(
        "PHI middleware added to FastAPI application (audit_mode=%s)",
        audit_mode
    )