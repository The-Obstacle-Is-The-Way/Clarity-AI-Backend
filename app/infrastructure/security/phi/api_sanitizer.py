"""
HIPAA-compliant API response sanitization middleware.

This module provides FastAPI middleware that automatically sanitizes
all API responses to prevent accidental PHI exposure.
"""

import json
import time
from typing import Any, Callable, Dict, List, Optional, Union, cast

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .phi_service import PHIService
from .log_sanitizer import LogSanitizer, get_sanitized_logger

# Create a sanitized logger
logger = get_sanitized_logger(__name__)


class PHISanitizerMiddleware(BaseHTTPMiddleware):
    """
    Middleware to sanitize PHI in API responses.
    
    This middleware intercepts all responses from the API and sanitizes
    any PHI in the response body before returning it to the client.
    """
    
    def __init__(
        self, 
        app: ASGIApp, 
        phi_service: Optional[PHIService] = None,
        log_sanitizer: Optional[LogSanitizer] = None,
        exclude_paths: Optional[List[str]] = None,
        sensitivity: str = 'medium',
        audit_all_responses: bool = False
    ):
        """
        Initialize the PHI sanitizer middleware.
        
        Args:
            app: The ASGI application
            phi_service: Optional PHIService for PHI detection and sanitization
            log_sanitizer: Optional LogSanitizer for sanitizing log messages
            exclude_paths: Optional list of paths to exclude from sanitization
            sensitivity: Default sensitivity level for sanitization
            audit_all_responses: Whether to log all responses for audit purposes
        """
        super().__init__(app)
        self.phi_service = phi_service or PHIService()
        self.log_sanitizer = log_sanitizer or LogSanitizer(phi_service=self.phi_service)
        self.exclude_paths = exclude_paths or []
        self.sensitivity = sensitivity
        self.audit_all_responses = audit_all_responses
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process an incoming request and sanitize the response.
        
        Args:
            request: The incoming request
            call_next: Function to call the next middleware/route handler
            
        Returns:
            Sanitized response
        """
        # Skip sanitization for excluded paths
        for path in self.exclude_paths:
            if request.url.path.startswith(path):
                return await call_next(request)
        
        # Process the request with timing for performance monitoring
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Skip sanitization for non-JSON responses
        content_type = response.headers.get("content-type")
        if not content_type or "application/json" not in content_type.lower():
            return response
            
        # Get original response body
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk
            
        # Skip empty responses
        if not response_body:
            return response
            
        # Sanitize the response body
        try:
            # Parse JSON response
            body_json = json.loads(response_body)
            
            # Sanitize the body
            sanitized_body = self.phi_service.sanitize_dict(body_json)
            
            # Audit responses if enabled
            if self.audit_all_responses:
                # Calculate PHI detection stats
                has_phi = False
                if isinstance(body_json, dict):
                    for key in body_json:
                        if isinstance(body_json[key], str):
                            phi_detection = self.phi_service.detect_phi(body_json[key])
                            if phi_detection["contains_phi"]:
                                has_phi = True
                                break
                                
                logger.info(
                    "API Response Audit: %s %s - PHI Detected: %s - Processing Time: %.3fs",
                    request.method,
                    request.url.path,
                    "Yes" if has_phi else "No",
                    process_time
                )
                
                if has_phi:
                    logger.warning(
                        "PHI detected in API response for %s %s - Types: %s",
                        request.method,
                        request.url.path,
                        ", ".join([phi_type.name for phi_type in phi_detection["phi_types"]])
                    )
            
            # Create new response with sanitized body
            return JSONResponse(
                content=sanitized_body,
                status_code=response.status_code,
                headers=dict(response.headers),
            )
            
        except json.JSONDecodeError:
            # Non-JSON response, return as is
            return response
        except Exception as e:
            # Log error and return original response
            logger.exception("Error sanitizing API response: %s", str(e))
            return response


class RequestBodySanitizerMiddleware(BaseHTTPMiddleware):
    """
    Middleware to sanitize PHI in request bodies for logging purposes.
    
    This middleware does not modify the actual request body used by handlers,
    but provides a sanitized version for logging and debugging.
    """
    
    def __init__(
        self, 
        app: ASGIApp, 
        phi_service: Optional[PHIService] = None,
        exclude_paths: Optional[List[str]] = None,
        sensitivity: str = 'medium'
    ):
        """
        Initialize the request body sanitizer middleware.
        
        Args:
            app: The ASGI application
            phi_service: Optional PHIService for PHI detection and sanitization
            exclude_paths: Optional list of paths to exclude from sanitization
            sensitivity: Default sensitivity level for sanitization
        """
        super().__init__(app)
        self.phi_service = phi_service or PHIService()
        self.exclude_paths = exclude_paths or []
        self.sensitivity = sensitivity
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process an incoming request, create a sanitized copy for logging.
        
        Args:
            request: The incoming request
            call_next: Function to call the next middleware/route handler
            
        Returns:
            Original response
        """
        # Skip sanitization for excluded paths
        for path in self.exclude_paths:
            if request.url.path.startswith(path):
                return await call_next(request)
        
        # Only process JSON requests
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type.lower():
            try:
                # Create a copy of the request body for sanitization
                body = await request.body()
                if body:
                    # Parse and sanitize the body
                    body_json = json.loads(body)
                    sanitized_body = self.phi_service.sanitize_dict(body_json)
                    
                    # Attach sanitized body to request state for logging middleware
                    request.state.sanitized_body = sanitized_body
            except Exception as e:
                logger.warning("Error sanitizing request body: %s", str(e))
                
        # Continue processing with original request
        return await call_next(request)


def add_phi_sanitizer_middleware(
    app: FastAPI,
    phi_service: Optional[PHIService] = None,
    exclude_paths: Optional[List[str]] = None,
    sensitivity: str = 'medium',
    audit_all_responses: bool = False
) -> None:
    """
    Add PHI sanitizer middleware to a FastAPI application.
    
    Args:
        app: FastAPI application instance
        phi_service: Optional PHIService instance
        exclude_paths: Paths to exclude from sanitization
        sensitivity: Default sensitivity level
        audit_all_responses: Whether to log all responses
    """
    # Create PHI service if not provided
    phi_service = phi_service or PHIService()
    log_sanitizer = LogSanitizer(phi_service=phi_service)
    
    # Default excluded paths
    if exclude_paths is None:
        exclude_paths = [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/static",
            "/metrics",
            "/health",
        ]
    
    # Add request body sanitizer first (inner middleware)
    app.add_middleware(
        RequestBodySanitizerMiddleware,
        phi_service=phi_service,
        exclude_paths=exclude_paths,
        sensitivity=sensitivity
    )
    
    # Add response sanitizer middleware
    app.add_middleware(
        PHISanitizerMiddleware,
        phi_service=phi_service,
        log_sanitizer=log_sanitizer,
        exclude_paths=exclude_paths,
        sensitivity=sensitivity,
        audit_all_responses=audit_all_responses
    )
    
    logger.info("PHI Sanitizer middleware added to FastAPI application")