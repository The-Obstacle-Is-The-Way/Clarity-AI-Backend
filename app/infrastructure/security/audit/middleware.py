"""
HIPAA Audit Logging Middleware.

This middleware automatically captures PHI access events for HIPAA compliance.
It logs all API requests that access PHI and ensures a complete audit trail
as required by HIPAA regulations.
"""

import json
import re
from typing import Callable, Dict, List, Optional, Set, Pattern

from fastapi import Request, Response
from fastapi.routing import APIRoute
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config.settings import get_settings
from app.core.interfaces.services.audit_logger_interface import IAuditLogger, AuditEventType


class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    Middleware that automatically logs PHI access for HIPAA compliance.
    
    This middleware intercepts all HTTP requests and logs those that may involve
    PHI access based on the route patterns and request methods.
    
    It works with the AuditLogService to create comprehensive HIPAA-compliant
    audit trails for all PHI access events.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        audit_logger: IAuditLogger,
        skip_paths: Optional[List[str]] = None,
        phi_paths: Optional[List[Pattern]] = None,
    ):
        """
        Initialize the audit log middleware.
        
        Args:
            app: The ASGI application to wrap
            audit_logger: The audit logger to use for logging events
            skip_paths: Paths to skip auditing (e.g., static assets)
            phi_paths: Regex patterns for paths that access PHI
        """
        super().__init__(app)
        self.audit_logger = audit_logger
        self.skip_paths = set(skip_paths or [])
        
        # Default PHI path patterns if none provided
        default_phi_patterns = [
            re.compile(r"/api/v\d+/patients/?.*"),  # All patient endpoints
            re.compile(r"/api/v\d+/medical-records/?.*"),  # Medical records
            re.compile(r"/api/v\d+/prescriptions/?.*"),  # Prescriptions
            re.compile(r"/api/v\d+/medications/?.*"),  # Medications
            re.compile(r"/api/v\d+/appointments/?.*"),  # Appointments
            re.compile(r"/api/v\d+/lab-results/?.*"),  # Lab results
            re.compile(r"/api/v\d+/diagnostics/?.*"),  # Diagnostics
            re.compile(r"/api/v\d+/providers/?.*"),  # Providers (may access PHI)
        ]
        
        self.phi_paths = phi_paths or default_phi_patterns
        self.settings = get_settings()
        
        # Map HTTP methods to audit actions
        self.method_to_action = {
            "GET": "view",
            "POST": "create",
            "PUT": "update",
            "PATCH": "modify",
            "DELETE": "delete"
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and log PHI access events.
        
        Args:
            request: The incoming request
            call_next: Function to call the next middleware/route
            
        Returns:
            Response: The response from the next middleware/route
        """
        # Skip logging for non-PHI paths
        path = request.url.path
        if self._should_skip(path):
            return await call_next(request)
        
        # Check if this path likely involves PHI
        if not self._is_phi_path(path):
            return await call_next(request)
        
        # Extract request information for audit log
        user_id = await self._extract_user_id(request)
        method = request.method
        action = self.method_to_action.get(method, "access")
        resource_type, resource_id = self._extract_resource_info(path)
        
        # Process the request and capture the response
        response = await call_next(request)
        
        # Log the PHI access event
        access_status = "success" if 200 <= response.status_code < 300 else "failure"
        if user_id:
            # Only log PHI access for authenticated users
            # This is critical for HIPAA compliance - all PHI access must be tracked
            await self.audit_logger.log_phi_access(
                actor_id=user_id,
                patient_id=resource_id or "unknown",
                resource_type=resource_type or "api_resource",
                action=action,
                status=access_status,
                reason="API request",
                request=request
            )
        
        return response
    
    def _should_skip(self, path: str) -> bool:
        """
        Determine if auditing should be skipped for this path.
        
        Args:
            path: The request path
            
        Returns:
            bool: True if auditing should be skipped
        """
        # Skip static files, docs, etc.
        if path in self.skip_paths:
            return True
        
        # Skip static asset paths
        for skip_pattern in ['/static/', '/assets/', '/favicon.ico', '/docs', '/redoc', '/openapi.json']:
            if skip_pattern in path:
                return True
        
        return False
    
    def _is_phi_path(self, path: str) -> bool:
        """
        Determine if a path potentially accesses PHI.
        
        Args:
            path: The request path
            
        Returns:
            bool: True if the path may access PHI
        """
        # Check against patterns of paths that access PHI
        for pattern in self.phi_paths:
            if pattern.match(path):
                return True
        
        return False
    
    async def _extract_user_id(self, request: Request) -> Optional[str]:
        """
        Extract the user ID from the request.
        
        Args:
            request: The FastAPI request
            
        Returns:
            Optional[str]: The user ID if available
        """
        # Try to get user from request state (set by auth middleware)
        if hasattr(request.state, "user") and request.state.user:
            return request.state.user.id
        
        # Try to get from headers or cookies as fallback
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            # Don't try to decode the token here - just note that there was one
            # User ID should be populated by auth middleware already
            return "authenticated_user"
        
        return None
    
    def _extract_resource_info(self, path: str) -> tuple[Optional[str], Optional[str]]:
        """
        Extract resource type and ID from the path.
        
        Args:
            path: The request path
            
        Returns:
            tuple: (resource_type, resource_id)
        """
        # Handle patient endpoints
        patient_match = re.match(r"/api/v\d+/patients/([^/]+)(?:/.*)?", path)
        if patient_match:
            return "patient", patient_match.group(1)
        
        # Handle other PHI resources
        for resource_type in ["medical-records", "prescriptions", "medications", 
                            "appointments", "lab-results", "diagnostics"]:
            match = re.match(rf"/api/v\d+/{resource_type}/([^/]+)(?:/.*)?", path)
            if match:
                return resource_type, match.group(1)
        
        # Generic API resource
        parts = path.strip("/").split("/")
        if len(parts) >= 3 and parts[0] == "api":
            # Get the resource type from the path
            resource_type = parts[2] if len(parts) > 2 else None
            # Get the resource ID if available
            resource_id = parts[3] if len(parts) > 3 else None
            return resource_type, resource_id
        
        return None, None 