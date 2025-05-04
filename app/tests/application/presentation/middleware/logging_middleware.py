"""
Logging middleware for FastAPI applications.

This middleware logs HTTP request and response details for auditing and debugging purposes.
It implements HIPAA-compliant logging by sanitizing PHI from logs.
"""

import json
import time
import uuid

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config.settings import get_settings
from app.core.utils.data_transformation import DataAnonymizer  # For PHI anonymization
from app.core.utils.logging import get_logger

logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging HTTP requests and responses.
    
    This middleware logs details about incoming requests and outgoing responses,
    including timing information, status codes, and sanitized payloads.
    """
    
    def __init__(
        self,
        app: FastAPI,
        exclude_paths: list[str] | None = None,
        log_request_body: bool = False,
        log_response_body: bool = False,
    ):
        """
        Initialize the logging middleware.
        
        Args:
            app: The FastAPI application
            exclude_paths: Paths to exclude from logging
            log_request_body: Whether to log request bodies
            log_response_body: Whether to log response bodies
        """
        super().__init__(app)
        self.exclude_paths = set(exclude_paths or [])
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body
        self.settings = get_settings()
        self.anonymizer = DataAnonymizer()
        
        # Add default excluded paths like health check endpoints
        self.exclude_paths.update([
            "/health",
            "/metrics",
            "/favicon.ico",
        ])
        
        logger.info(
            "LoggingMiddleware initialized. Excluded paths: %s, "
            "Log request body: %s, Log response body: %s",
            list(self.exclude_paths),
            self.log_request_body,
            self.log_response_body
        )
        
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """
        Process the request and log relevant information.
        
        This method is called for each request passing through the middleware.
        It logs request details, calls the next middleware/endpoint, and logs
        the response details.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware or endpoint to call
            
        Returns:
            The HTTP response
        """
        # Skip logging for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        # Generate a unique request ID for tracing
        request_id = str(uuid.uuid4())
        
        # Start timing the request
        start_time = time.time()
        
        # Log request details, sanitizing potential PHI
        await self._log_request(request, request_id)
        
        # Set the request ID in the request state for downstream use
        request.state.request_id = request_id
        
        try:
            # Process the request through the rest of the middleware chain and route handlers
            response = await call_next(request)
            
            # Calculate request processing time
            process_time = time.time() - start_time
            
            # Add timing header to response
            response.headers["X-Process-Time"] = str(process_time)
            
            # Log response details
            await self._log_response(request, response, process_time, request_id)
            
            return response
            
        except Exception as exc:
            # Log unhandled exceptions
            process_time = time.time() - start_time
            logger.exception(
                "Unhandled exception in request %s %s (ID: %s): %s. "
                "Processed in %.4f seconds",
                request.method,
                self.anonymizer.anonymize_text(str(request.url)),
                request_id,
                str(exc),
                process_time
            )
            # Re-raise to allow exception handlers to process it
            raise
            
    async def _log_request(self, request: Request, request_id: str) -> None:
        """
        Log details about the incoming request.
        
        Args:
            request: The HTTP request
            request_id: Unique identifier for this request
        """
        # Get client info with sanitization for HIPAA compliance
        client_host = self.anonymizer.anonymize_text(request.client.host)
        path = self.anonymizer.anonymize_text(str(request.url.path))
        
        # Basic request logging
        log_data = {
            "request_id": request_id,
            "client_host": client_host,
            "method": request.method,
            "path": path,
            "query_params": {},  # Will be populated if available
            "headers": {},  # Will be populated selectively
        }
        
        # Log query parameters with sanitization
        if request.query_params:
            # Convert to dict and sanitize keys/values
            params_dict = dict(request.query_params.items())
            sanitized_params = {}
            for key, value in params_dict.items():
                sanitized_key = self.anonymizer.anonymize_text(key)
                sanitized_value = self.anonymizer.anonymize_text(value)
                sanitized_params[sanitized_key] = sanitized_value
            log_data["query_params"] = sanitized_params
            
        # Selectively log important headers, omitting sensitive ones
        important_headers = [
            "user-agent", "accept", "content-type", "content-length",
            "x-request-id", "x-forwarded-for", "x-real-ip"
        ]
        headers_dict = {}
        for header in important_headers:
            if header in request.headers:
                value = request.headers.get(header)
                # Sanitize header value just in case
                headers_dict[header] = self.anonymizer.anonymize_text(value)
        log_data["headers"] = headers_dict
        
        # Optionally log request body with sanitization (should be disabled in production for PHI safety)
        if self.log_request_body and self.settings.ENVIRONMENT != "production":
            try:
                body = await request.body()
                if body:
                    try:
                        # Try to parse as JSON
                        body_dict = json.loads(body)
                        # Sanitize the body dict recursively
                        sanitized_body = self._sanitize_dict(body_dict)
                        log_data["body"] = sanitized_body
                    except json.JSONDecodeError:
                        # Not JSON, log as sanitized string
                        body_str = body.decode("utf-8", errors="replace")
                        log_data["body"] = self.anonymizer.anonymize_text(body_str)
            except Exception as e:
                logger.warning("Could not log request body: %s", str(e))
                
        # Log the request with structured data
        logger.info("Request received: %s %s (ID: %s)", 
                    request.method, path, request_id, 
                    extra={"log_data": log_data})
        
    async def _log_response(
        self, request: Request, response: Response, process_time: float, request_id: str
    ) -> None:
        """
        Log details about the outgoing response.
        
        Args:
            request: The HTTP request
            response: The HTTP response
            process_time: Time taken to process the request
            request_id: Unique identifier for this request
        """
        # Sanitize path for logging
        path = self.anonymizer.anonymize_text(str(request.url.path))
        
        # Basic response logging
        log_data = {
            "request_id": request_id,
            "method": request.method,
            "path": path,
            "status_code": response.status_code,
            "process_time": f"{process_time:.4f}s",
            "headers": {},  # Will be populated selectively
        }
        
        # Selectively log important response headers
        important_headers = [
            "content-type", "content-length", "x-process-time"
        ]
        headers_dict = {}
        for header in important_headers:
            if header in response.headers:
                headers_dict[header] = response.headers.get(header)
        log_data["headers"] = headers_dict
        
        # Optionally log response body (should be disabled in production for PHI safety)
        if self.log_response_body and self.settings.ENVIRONMENT != "production":
            # This requires modifying the response object to access its body
            # which can be complex and is not recommended for production
            # A better approach is to log response bodies in development only
            pass
            
        # Determine appropriate log level based on status code
        if response.status_code >= 500:
            logger.error(
                "Response sent: %s %s %d (ID: %s) in %.4f seconds",
                request.method, path, response.status_code, request_id, process_time,
                extra={"log_data": log_data}
            )
        elif response.status_code >= 400:
            logger.warning(
                "Response sent: %s %s %d (ID: %s) in %.4f seconds",
                request.method, path, response.status_code, request_id, process_time,
                extra={"log_data": log_data}
            )
        else:
            logger.info(
                "Response sent: %s %s %d (ID: %s) in %.4f seconds",
                request.method, path, response.status_code, request_id, process_time,
                extra={"log_data": log_data}
            )
            
    def _sanitize_dict(self, data: dict) -> dict:
        """
        Recursively sanitize a dictionary to remove PHI.
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data
            
        sanitized = {}
        for key, value in data.items():
            # Sanitize the key
            sanitized_key = self.anonymizer.anonymize_text(str(key))
            
            # Recursively sanitize values based on type
            if isinstance(value, dict):
                sanitized_value = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized_value = [
                    self._sanitize_dict(item) if isinstance(item, dict)
                    else self.anonymizer.anonymize_text(str(item))
                    for item in value
                ]
            elif value is not None:
                sanitized_value = self.anonymizer.anonymize_text(str(value))
            else:
                sanitized_value = None
                
            sanitized[sanitized_key] = sanitized_value
            
        return sanitized
