"""
HIPAA-compliant audit logging middleware.

This middleware provides comprehensive audit logging for API calls, with special
handling for PHI access to ensure HIPAA compliance.
"""

import re
import ipaddress 
import logging
from typing import Callable, List, Pattern, Dict, Any, Tuple, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from sqlalchemy.exc import SQLAlchemyError

from app.core.config.settings import get_settings
from app.core.interfaces.services.audit_logger_interface import IAuditLogger, AuditEventType

# Initialize logger
logger = logging.getLogger(__name__)

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
    
    def _is_audit_disabled(self, request: Request) -> bool:
        """
        Check if audit logging is disabled for this request.
        
        This checks both app.state and request.state for the disable_audit_middleware flag.
        
        Args:
            request: The FastAPI request
            
        Returns:
            bool: True if audit logging should be disabled
        """
        # Check if we're in a test environment from app state first
        if hasattr(request.app.state, "testing") and request.app.state.testing:
            logger.debug("Test environment flag detected on app.state.testing - audit logging disabled")
            return True
            
        # Check request.state first (higher priority)
        if hasattr(request.state, "disable_audit_middleware") and request.state.disable_audit_middleware:
            logger.debug("Audit logging disabled via request.state.disable_audit_middleware")
            return True
            
        # Then check app.state
        if hasattr(request.app.state, "disable_audit_middleware") and request.app.state.disable_audit_middleware:
            logger.debug("Audit logging disabled via app.state.disable_audit_middleware")
            return True
            
        # Check if audit logger is properly configured and available
        if not self.audit_logger:
            logger.warning("Audit logger not available - disabling audit logging")
            return True
            
        # Check if we're in a test environment
        settings = request.state.settings if hasattr(request.state, "settings") else self.settings
        if settings.ENVIRONMENT == "test":
            # In test environments, default to disabled unless explicitly enabled
            logger.debug("Test environment detected from settings - audit logging disabled by default")
            return True
            
        return False
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and log relevant audit information.
        
        Args:
            request: The FastAPI request
            call_next: The next middleware or endpoint handler
            
        Returns:
            Response: The response from the next handler
        """
        # Check if audit logging is disabled
        if self._is_audit_disabled(request):
            return await call_next(request)
            
        # Skip paths that shouldn't be audited
        path = request.url.path
        method = request.method
        
        if self._should_skip(path):
            return await call_next(request)
            
        # Check if this path potentially accesses PHI
        is_phi_path = self._is_phi_path(path)
        
        # Extract the user ID from the request
        user_id = None
        try:
            user_id = await self._extract_user_id(request)
        except Exception as e:
            logger.warning(f"Failed to extract user ID from request: {e}")
            if self.settings.ENVIRONMENT == "test":
                logger.debug(f"Detailed error extracting user ID: {e}", exc_info=True)
            user_id = "unknown"
        
        # Extract request information for audit log
        action = self.method_to_action.get(method, "access")
        resource_type, resource_id = self._extract_resource_info(path)
        
        # Create request context for additional security information
        request_context = None
        try:
            request_context = await self._create_request_context(request)
        except Exception as e:
            logger.warning(f"Failed to create request context: {e}")
            if self.settings.ENVIRONMENT == "test":
                logger.debug(f"Detailed error creating request context: {e}", exc_info=True)
            request_context = {"error": str(e)}
        
        # Process the request and capture the response
        response = None
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            logger.error(f"Unhandled exception in middleware chain: {e}")
            status_code = 500
            raise e
        finally:
            try:
                # Only proceed with logging if we have a valid response and user ID
                if response and user_id and user_id != "unknown":
                    # Log PHI access if this is a PHI path
                    if is_phi_path:
                        access_status = "success" if 200 <= status_code < 300 else "failure"
                        
                        try:
                            await self.audit_logger.log_phi_access(
                                actor_id=user_id,
                                patient_id=resource_id or "unknown",
                                resource_type=resource_type or "api_resource",
                                action=action,
                                status=access_status,
                                reason="API request",
                                request=request,
                                request_context=request_context
                            )
                        except SQLAlchemyError as db_error:
                            # Log error but don't fail the request
                            logger.error(f"Failed to log PHI access due to database error: {db_error}")
                            if self.settings.ENVIRONMENT == "test":
                                logger.debug(f"Database error details: {db_error}", exc_info=True)
                        except Exception as e:
                            # Log any other unexpected errors
                            logger.error(f"Failed to log PHI access: {e}")
                            if self.settings.ENVIRONMENT == "test":
                                logger.debug(f"Detailed error logging PHI access: {e}", exc_info=True)
                    else:
                        # For non-PHI paths, log API access
                        try:
                            await self.audit_logger.log_event(
                                event_type=AuditEventType.API_REQUEST,
                                actor_id=user_id,
                                target_resource=resource_type,
                                target_id=resource_id,
                                action=action,
                                status="success" if 200 <= status_code < 300 else "failure",
                                details={"path": path, "method": method, "status_code": status_code},
                                request=request
                            )
                        except SQLAlchemyError as db_error:
                            # Log error but don't fail the request
                            logger.error(f"Failed to log API request due to database error: {db_error}")
                            if self.settings.ENVIRONMENT == "test":
                                logger.debug(f"Database error details: {db_error}", exc_info=True)
                        except Exception as e:
                            # Log any other unexpected errors
                            logger.error(f"Failed to log API request: {e}")
                            if self.settings.ENVIRONMENT == "test":
                                logger.debug(f"Detailed error logging API access: {e}", exc_info=True)
            except Exception as outer_e:
                # Catch-all for any errors in the logging logic to ensure response is always returned
                logger.error(f"Unhandled exception in audit logging logic: {outer_e}")
                if self.settings.ENVIRONMENT == "test":
                    logger.debug(f"Detailed error in audit logging: {outer_e}", exc_info=True)
        
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
        if any(path.startswith(skip_path) or path == skip_path for skip_path in self.skip_paths):
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
    
    async def _extract_user_id(self, request: Request) -> str:
        """
        Extract user ID from request.
        
        Args:
            request: The FastAPI request
            
        Returns:
            str: User ID or placeholder value
        """
        # Primary method: Get from authenticated user in request state
        if hasattr(request.state, "user") and request.state.user is not None:
            return request.state.user.id
        
        # Secondary method: Try to extract from auth token
        if "Authorization" in request.headers:
            try:
                # Get settings from request state if available, else from global
                settings = request.state.settings if hasattr(request.state, "settings") else get_settings()
                
                # Get JWT service from request state if available
                jwt_service = getattr(request.state, "jwt_service", None)
                
                # Extract token
                auth_header = request.headers["Authorization"]
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]  # Remove "Bearer " prefix
                    if jwt_service:
                        try:
                            payload = await jwt_service.decode_token(token)
                            if payload and hasattr(payload, "sub"):
                                return payload.sub
                        except Exception as e:
                            # Log token validation error but continue
                            logger.warning(f"Error validating token in audit middleware: {e}")
                    
                    # In test mode, use a fixed value to avoid requiring complex JWT setup
                    if settings.ENVIRONMENT == "test":
                        return "test_user"
                    return "authenticated_user"  # Fallback if we can't extract user ID from token
            except Exception as e:
                logger.warning(f"Error processing Authorization header: {e}")
        
        # Fallback: Use anonymous user ID
        return "anonymous"
    
    def _extract_resource_info(self, path: str) -> Tuple[Optional[str], Optional[str]]:
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
    
    async def _create_request_context(self, request: Request) -> Dict[str, Any]:
        """
        Create rich context information from the request for security analysis.
        
        Args:
            request: The request object
            
        Returns:
            Dict[str, Any]: Context information for security analysis
        """
        # Extract IP address
        client_host = request.client.host if request.client else None
        
        # Extract user agent
        user_agent = request.headers.get("user-agent", "")
        
        # Extract other relevant headers
        relevant_headers = {
            "referer": request.headers.get("referer", ""),
            "origin": request.headers.get("origin", ""),
            "x-forwarded-for": request.headers.get("x-forwarded-for", ""),
            "x-real-ip": request.headers.get("x-real-ip", "")
        }
        
        # Try to get general location info without external API calls
        location_info = None
        if client_host:
            try:
                # Check if it's a private IP
                ip_obj = ipaddress.ip_address(client_host)
                is_private = ip_obj.is_private
                location_info = {"is_private": is_private}
            except Exception:
                location_info = {"error": "Could not parse IP address"}
        
        # Collect everything into a context object
        context = {
            "ip": client_host,
            "user_agent": user_agent,
            "headers": relevant_headers,
            "location": location_info,
            "url": str(request.url),
            "method": request.method,
        }
        
        return context 