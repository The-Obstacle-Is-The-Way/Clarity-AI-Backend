"""
HIPAA-compliant middleware for PHI protection in API endpoints.

This module provides FastAPI middleware components to protect PHI in
requests and responses, ensuring HIPAA compliance at the API layer.
"""

import json
import time
from collections.abc import Callable
from typing import Any, Dict, List, Set, Union

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# Import from consolidated sanitizer implementation
from .sanitizer import PHISanitizer, get_sanitized_logger

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
        phi_sanitizer: PHISanitizer | None = None,
        audit_mode: bool = False,
        exclude_paths: list[str] | None = None,
        whitelist_patterns: dict[str, list[str]] | list[str] | None = None
    ):
        """
        Initialize PHI middleware.
        
        Args:
            app: The ASGI application
            phi_sanitizer: Optional PHISanitizer for PHI detection and sanitization
            audit_mode: Whether to log PHI exposure without sanitizing
            exclude_paths: Optional list of paths to exclude from sanitization
            whitelist_patterns: Optional dict of paths to patterns or list of global patterns to exclude from sanitization
        """
        super().__init__(app)
        self.audit_mode = audit_mode
        self.exclude_paths = exclude_paths or []
        
        # Store whitelist_patterns as instance variable for use in is_whitelisted_by_middleware
        self.whitelist_patterns = whitelist_patterns
        
        # Process whitelist_patterns argument for PHISanitizer init
        _sanitizer_path_whitelist: dict[str, list[str]] = {}
        _sanitizer_global_whitelist_list: list[str] = []

        if whitelist_patterns is None:
            pass # Keep them empty for PHISanitizer
        elif isinstance(whitelist_patterns, dict):
            _sanitizer_path_whitelist = whitelist_patterns
        elif isinstance(whitelist_patterns, list):
            _sanitizer_global_whitelist_list = whitelist_patterns
        else:
            logger.warning(f"Invalid whitelist_patterns format for PHIMiddleware: {type(whitelist_patterns)}")
        
        # Configure the PHISanitizer instance
        self.phi_sanitizer = phi_sanitizer or PHISanitizer(
            whitelist_patterns=set(_sanitizer_global_whitelist_list), 
            path_whitelist_patterns=_sanitizer_path_whitelist
        )
        
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
    
    def is_whitelisted_by_middleware(self, text: str, path: str) -> bool:
        """
        Check if text is whitelisted for the current path based on middleware configuration.
        
        This is separate from PHISanitizer's internal whitelist and provides an additional
        layer of path-specific control at the middleware level.
        
        Args:
            text: Text to check
            path: Current request path
            
        Returns:
            True if text is whitelisted, False otherwise
        """
        # First check explicit path-specific whitelist patterns
        if path and self.whitelist_patterns:
            # Handle dict-style whitelist (path -> patterns)
            if isinstance(self.whitelist_patterns, dict):
                # Find applicable path patterns
                for whitelist_path, field_patterns in self.whitelist_patterns.items():
                    # Check if current path matches this whitelist path
                    if path.startswith(whitelist_path) or (
                        '*' in whitelist_path and 
                        path.startswith(whitelist_path.split('*')[0])
                    ):
                        # Path matches, check if text matches any field pattern
                        if isinstance(field_patterns, list):
                            for pattern in field_patterns:
                                # Handle string patterns (exact match)
                                if isinstance(pattern, str) and pattern in text:
                                    return True
                                # Handle regex patterns (search)
                                elif hasattr(pattern, 'search') and pattern.search(text):
                                    return True
            # Handle list-style global whitelist
            elif isinstance(self.whitelist_patterns, list):
                for pattern in self.whitelist_patterns:
                    # Handle string patterns (exact match)
                    if isinstance(pattern, str) and pattern in text:
                        return True
                    # Handle regex patterns (search)
                    elif hasattr(pattern, 'search') and pattern.search(text):
                        return True
                        
        # Special case for non-PHI fields that are commonly over-redacted
        safe_fields = {
            "appointment_date", "date", "created_at", "updated_at", 
            "provider", "insurance_provider", "status", "type",
            "appointment.date"
        }
        if text in safe_fields:
            return True
            
        # Default to False - not whitelisted by the middleware
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
        # Get the current path for whitelist checking
        current_path = request.url.path
        
        # Skip excluded paths
        if self.is_excluded_path(current_path):
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
            
            # Check for PHI in the response, considering whitelisted patterns
            contains_phi = self._check_for_phi(body_json, current_path)
            
            # Sanitize or audit the response
            if contains_phi:
                logger.warning(
                    "PHI detected in API response for %s %s",
                    request.method,
                    current_path
                )
                
                if self.audit_mode:
                    # In audit mode, log the finding but don't modify the response
                    logger.info(
                        "Audit mode: PHI would be sanitized in response to %s %s",
                        request.method,
                        current_path
                    )
                    sanitized_body = body_json
                else:
                    # Sanitize the response body, preserving whitelisted patterns
                    sanitized_body = self._sanitize_response_json(body_json, current_path)
                    logger.info(
                        "PHI sanitized in response to %s %s",
                        request.method,
                        current_path
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
                current_path,
                process_time
            )
            
            # Add security headers
            self._add_security_headers(response)
            
            return response
            
        except json.JSONDecodeError:
            # Not a valid JSON response.
            # Return a new Response with the original (non-JSON) body, status, and headers.
            logger.debug(
                "Response from %s %s was not valid JSON. Returning as is.",
                request.method,
                current_path
            )
            new_response = Response( # Create a new Response object
                content=response_body, # Use the original body bytes
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            self._add_security_headers(new_response) # Add headers to the new response
            return new_response # Return the new response
        except Exception as e:
            # Log the error and return the original response
            logger.error(
                "Error processing response from %s %s: %s",
                request.method,
                current_path,
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
            current_path = request.url.path
            contains_phi = self._check_for_phi(body_json, current_path)
            
            if contains_phi:
                # Log a warning about PHI in the request (without including the PHI)
                logger.warning(
                    "PHI detected in request to %s %s",
                    request.method,
                    current_path
                )
                
                # Create a sanitized version for debugging if needed
                sanitized_json = self._sanitize_response_json(body_json, current_path)
                
                # We could log the sanitized body here, but we don't to minimize logging
                logger.debug("Request body contained PHI and was sanitized for logging")
                
        except json.JSONDecodeError:
            # Not a valid JSON request, nothing to sanitize
            pass
        except Exception as e:
            # Log the error and continue
            logger.error(
                "Error sanitizing request body from %s %s: %s",
                request.method,
                request.url.path,
                str(e)
            )
    
    def _check_for_phi(self, data: Any, path: str) -> bool:
        """
        Check for PHI in data, delegating to PHISanitizer with path context.
        
        Args:
            data: Data to check (JSON structure)
            path: Current request path
            
        Returns:
            True if PHI is detected that is not whitelisted, False otherwise
        """
        if isinstance(data, dict):
            for key, value in data.items():
                # Check if key or value contains PHI
                if isinstance(key, str) and self.phi_sanitizer.contains_phi(key, path=path):
                    return True
                
                # Skip whitelisted keys even for recursive checks
                if self.is_whitelisted_by_middleware(key, path):
                    continue
                    
                # Check value recursively
                if self._check_for_phi(value, path):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._check_for_phi(item, path):
                    return True
        elif isinstance(data, str):
            # Check if string contains PHI, considering path-specific whitelist
            return self.phi_sanitizer.contains_phi(data, path=path)
        return False
    
    def _sanitize_response_json(self, data: Any, path: str) -> Any:
        """
        Sanitize JSON response data by removing PHI, respecting whitelists via PHISanitizer.
        
        Args:
            data: Parsed JSON data (dict or list)
            path: Current request path for context-aware whitelisting
            
        Returns:
            Sanitized JSON data
        """
        if data is None:
            return None
            
        # Handle different data types
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                # If key is whitelisted by the middleware or through a whitelist pattern,
                # preserve it without sanitization
                if self.is_whitelisted_by_middleware(key, path):
                    result[key] = value
                    continue
                
                # For certain safe fields that should never be redacted (like dates that aren't DOB),
                # preserve them without sanitization
                if key in {"appointment_date", "created_at", "updated_at", "status", "date", 
                          "provider", "insurance_provider", "appointment.date"}:
                    result[key] = value
                    continue
                    
                # Otherwise recursively sanitize the value
                result[key] = self._sanitize_response_json(value, path)
            return result
            
        elif isinstance(data, list):
            return [self._sanitize_response_json(item, path) for item in data]
            
        elif isinstance(data, str):
            # Skip sanitization for paths or fields that are explicitly whitelisted
            if self.is_whitelisted_by_middleware(data, path):
                return data
                
            # For all other strings, apply the PHI sanitizer with path context
            return self.phi_sanitizer.sanitize_string(data, path)
            
        # Non-string primitive types are returned as is
        return data
    
    def _add_security_headers(self, response: Response) -> None:
        """
        Add security headers to a response.
        
        Args:
            response: Response to add headers to
        """
        for header, value in self.security_headers.items():
            response.headers[header] = value


def get_phi_middleware(
    phi_sanitizer: PHISanitizer | None = None,
    audit_mode: bool = False,
    exclude_paths: list[str] | None = None,
    whitelist_patterns: dict[str, list[str]] | list[str] | None = None
) -> PHIMiddleware:
    """
    Factory function to create a PHI middleware instance.
    
    Args:
        phi_sanitizer: Optional PHISanitizer for PHI detection and sanitization
        audit_mode: Whether to log PHI exposure without sanitizing
        exclude_paths: Optional list of paths to exclude from sanitization
        whitelist_patterns: Optional dict of paths to patterns or list of global patterns 
                           to exclude from sanitization
    
    Returns:
        A configured PHIMiddleware instance
    """
    return lambda app: PHIMiddleware(
        app=app,
        phi_sanitizer=phi_sanitizer,
        audit_mode=audit_mode,
        exclude_paths=exclude_paths,
        whitelist_patterns=whitelist_patterns
    )


def add_phi_middleware(
    app: FastAPI,
    phi_sanitizer: PHISanitizer | None = None,
    audit_mode: bool = False,
    exclude_paths: list[str] | None = None,
    whitelist_patterns: dict[str, list[str]] | list[str] | None = None
) -> None:
    """
    Add PHI middleware to a FastAPI application.
    
    Args:
        app: FastAPI application to add middleware to
        phi_sanitizer: Optional PHISanitizer for PHI detection and sanitization
        audit_mode: Whether to log PHI exposure without sanitizing
        exclude_paths: Optional list of paths to exclude from sanitization  
        whitelist_patterns: Optional dict of paths to patterns or list of global patterns 
                           to exclude from sanitization
    """
    app.add_middleware(
        PHIMiddleware,
        phi_sanitizer=phi_sanitizer,
        audit_mode=audit_mode,
        exclude_paths=exclude_paths,
        whitelist_patterns=whitelist_patterns
    )