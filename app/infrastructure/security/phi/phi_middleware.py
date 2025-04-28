"""
PHI Middleware for HIPAA Compliance

This module provides middleware for FastAPI that detects and sanitizes PHI in
requests and responses, ensuring HIPAA compliance.
"""

import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple, Union
from enum import Enum

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import HTMLResponse, PlainTextResponse

from app.infrastructure.security.phi.phi_service import PHIService, PHIType

logger = logging.getLogger(__name__)

class PHIMiddlewareMode(Enum):
    """Modes for PHI middleware."""
    AUDIT = "audit"  # Log PHI but don't sanitize
    SANITIZE = "sanitize"  # Sanitize PHI in requests and responses
    BLOCK = "block"  # Block requests and responses with PHI


class PHIMiddleware(BaseHTTPMiddleware):
    """
    Middleware for detecting and sanitizing PHI in requests and responses.
    
    This middleware can operate in three modes:
    - AUDIT: Log PHI but don't sanitize
    - SANITIZE: Sanitize PHI in requests and responses
    - BLOCK: Block requests and responses with PHI
    """
    
    def __init__(
        self,
        app: FastAPI,
        mode: PHIMiddlewareMode = PHIMiddlewareMode.SANITIZE,
        whitelist_patterns: Optional[List[str]] = None,
        sensitivity: str = "medium",
        replacement_template: str = "[REDACTED {phi_type}]"
    ):
        """
        Initialize PHI middleware.
        
        Args:
            app: FastAPI application
            mode: Middleware mode (AUDIT, SANITIZE, BLOCK)
            whitelist_patterns: List of URL patterns to whitelist
            sensitivity: PHI detection sensitivity
            replacement_template: Template for PHI replacement
        """
        super().__init__(app)
        self.mode = mode
        self.phi_service = PHIService()
        self.sensitivity = sensitivity
        self.replacement_template = replacement_template
        
        # Compile whitelist patterns
        self.whitelist_patterns = []
        if whitelist_patterns:
            for pattern in whitelist_patterns:
                try:
                    self.whitelist_patterns.append(re.compile(pattern))
                except re.error:
                    logger.error(f"Invalid whitelist pattern: {pattern}")
        
        logger.info(f"PHI middleware initialized in {mode.value} mode")
    
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """
        Process request and response.
        
        Args:
            request: FastAPI request
            call_next: Next middleware in chain
            
        Returns:
            Response
        """
        # Check if request URL is whitelisted
        if self._is_whitelisted(request.url.path):
            logger.debug(f"Request URL {request.url.path} is whitelisted, skipping PHI checks")
            return await call_next(request)
        
        # Process request body if it exists
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                # Clone the request to avoid consuming the body
                body = await request.body()
                
                # If body exists, check for PHI
                if body:
                    # Try to parse as JSON
                    try:
                        body_json = json.loads(body)
                        contains_phi = self._check_data_for_phi(body_json)
                        
                        if contains_phi:
                            logger.warning(f"PHI detected in request body for {request.url.path}")
                            
                            if self.mode == PHIMiddlewareMode.BLOCK:
                                return JSONResponse(
                                    status_code=400,
                                    content={"detail": "Request contains PHI and was blocked"}
                                )
                            elif self.mode == PHIMiddlewareMode.SANITIZE:
                                # Sanitize the request body
                                sanitized_body = self.phi_service.sanitize(
                                    body_json,
                                    sensitivity=self.sensitivity,
                                    replacement=self.replacement_template
                                )
                                # Create a new request with sanitized body
                                request._body = json.dumps(sanitized_body).encode()
                    except json.JSONDecodeError:
                        # Not JSON, check as plain text
                        body_text = body.decode("utf-8", errors="replace")
                        contains_phi = self.phi_service.contains_phi(body_text, sensitivity=self.sensitivity)
                        
                        if contains_phi:
                            logger.warning(f"PHI detected in non-JSON request body for {request.url.path}")
                            
                            if self.mode == PHIMiddlewareMode.BLOCK:
                                return JSONResponse(
                                    status_code=400,
                                    content={"detail": "Request contains PHI and was blocked"}
                                )
                            elif self.mode == PHIMiddlewareMode.SANITIZE:
                                # Sanitize the request body
                                sanitized_body = self.phi_service.sanitize_text(
                                    body_text,
                                    sensitivity=self.sensitivity,
                                    replacement=self.replacement_template
                                )
                                # Create a new request with sanitized body
                                request._body = sanitized_body.encode()
            except Exception as e:
                logger.error(f"Error processing request body: {e}")
        
        # Call next middleware
        response = await call_next(request)
        
        # Process response
        if response.status_code < 400:  # Only process successful responses
            # Get response body
            response_body = b""
            
            # Store original response headers and status
            original_headers = response.headers.copy()
            original_status = response.status_code
            
            # Get response body
            if hasattr(response, "body"):
                response_body = response.body
            elif hasattr(response, "body_iterator"):
                # Consume the iterator to get the body
                chunks = [chunk async for chunk in response.body_iterator]
                response_body = b"".join(chunks)
            
            # Process response body if it exists
            if response_body:
                content_type = response.headers.get("content-type", "")
                
                # Process JSON response
                if "application/json" in content_type:
                    try:
                        body_json = json.loads(response_body)
                        contains_phi = self._check_data_for_phi(body_json)
                        
                        if contains_phi:
                            logger.warning(f"PHI detected in JSON response for {request.url.path}")
                            
                            if self.mode == PHIMiddlewareMode.BLOCK:
                                return JSONResponse(
                                    status_code=403,
                                    content={"detail": "Response contains PHI and was blocked"}
                                )
                            elif self.mode == PHIMiddlewareMode.SANITIZE:
                                # Sanitize the response body
                                sanitized_body = self.phi_service.sanitize(
                                    body_json,
                                    sensitivity=self.sensitivity,
                                    replacement=self.replacement_template
                                )
                                # Create a new response with sanitized body
                                return JSONResponse(
                                    status_code=original_status,
                                    content=sanitized_body,
                                    headers=original_headers
                                )
                    except json.JSONDecodeError:
                        logger.error(f"Error decoding JSON response for {request.url.path}")
                
                # Process HTML response
                elif "text/html" in content_type:
                    try:
                        body_text = response_body.decode("utf-8", errors="replace")
                        contains_phi = self.phi_service.contains_phi(body_text, sensitivity=self.sensitivity)
                        
                        if contains_phi:
                            logger.warning(f"PHI detected in HTML response for {request.url.path}")
                            
                            if self.mode == PHIMiddlewareMode.BLOCK:
                                return JSONResponse(
                                    status_code=403,
                                    content={"detail": "Response contains PHI and was blocked"}
                                )
                            elif self.mode == PHIMiddlewareMode.SANITIZE:
                                # Sanitize the response body
                                sanitized_body = self.phi_service.sanitize_text(
                                    body_text,
                                    sensitivity=self.sensitivity,
                                    replacement=self.replacement_template
                                )
                                # Create a new response with sanitized body
                                return HTMLResponse(
                                    content=sanitized_body,
                                    status_code=original_status,
                                    headers=original_headers
                                )
                    except Exception as e:
                        logger.error(f"Error processing HTML response: {e}")
                
                # Process plain text response
                elif "text/plain" in content_type:
                    try:
                        body_text = response_body.decode("utf-8", errors="replace")
                        contains_phi = self.phi_service.contains_phi(body_text, sensitivity=self.sensitivity)
                        
                        if contains_phi:
                            logger.warning(f"PHI detected in text response for {request.url.path}")
                            
                            if self.mode == PHIMiddlewareMode.BLOCK:
                                return JSONResponse(
                                    status_code=403,
                                    content={"detail": "Response contains PHI and was blocked"}
                                )
                            elif self.mode == PHIMiddlewareMode.SANITIZE:
                                # Sanitize the response body
                                sanitized_body = self.phi_service.sanitize_text(
                                    body_text,
                                    sensitivity=self.sensitivity,
                                    replacement=self.replacement_template
                                )
                                # Create a new response with sanitized body
                                return PlainTextResponse(
                                    content=sanitized_body,
                                    status_code=original_status,
                                    headers=original_headers
                                )
                    except Exception as e:
                        logger.error(f"Error processing text response: {e}")
        
        return response
    
    def _is_whitelisted(self, path: str) -> bool:
        """
        Check if path is whitelisted.
        
        Args:
            path: URL path
            
        Returns:
            True if path is whitelisted, False otherwise
        """
        return any(pattern.search(path) for pattern in self.whitelist_patterns)
    
    def _check_data_for_phi(self, data: Any) -> bool:
        """
        Check if data contains PHI.
        
        Args:
            data: Data to check
            
        Returns:
            True if data contains PHI, False otherwise
        """
        if isinstance(data, dict):
            # Check each value recursively
            for key, value in data.items():
                if self._check_data_for_phi(value):
                    return True
        elif isinstance(data, list):
            # Check each item recursively
            for item in data:
                if self._check_data_for_phi(item):
                    return True
        elif isinstance(data, str):
            # Check string for PHI
            return self.phi_service.contains_phi(data, sensitivity=self.sensitivity)
        
        return False


def add_phi_middleware(
    app: FastAPI,
    mode: str = "sanitize",
    whitelist_patterns: Optional[List[str]] = None,
    sensitivity: str = "medium",
    replacement_template: str = "[REDACTED {phi_type}]"
) -> None:
    """
    Add PHI middleware to FastAPI application.
    
    Args:
        app: FastAPI application
        mode: Middleware mode ("audit", "sanitize", "block")
        whitelist_patterns: List of URL patterns to whitelist
        sensitivity: PHI detection sensitivity
        replacement_template: Template for PHI replacement
    """
    # Convert mode string to enum
    middleware_mode = PHIMiddlewareMode.SANITIZE
    if mode == "audit":
        middleware_mode = PHIMiddlewareMode.AUDIT
    elif mode == "block":
        middleware_mode = PHIMiddlewareMode.BLOCK
    
    # Add middleware
    app.add_middleware(
        PHIMiddleware,
        mode=middleware_mode,
        whitelist_patterns=whitelist_patterns or [],
        sensitivity=sensitivity,
        replacement_template=replacement_template
    )
    
    logger.info(f"Added PHI middleware to FastAPI application in {mode} mode")
