"""
HIPAA-compliant error handling utilities.

This module provides centralized error handling functionality to prevent PHI exposure
in API responses while maintaining detailed internal logging for debugging purposes.
"""
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.interfaces.services.audit_logger_interface import IAuditLogger


class APIError(Exception):
    """Base exception class for all API errors."""
    
    status_code: int = 500
    error_type: str = "internal_error"
    default_message: str = "An internal server error occurred."
    
    def __init__(
        self, 
        message: str | None = None, 
        status_code: int | None = None,
        details: dict[str, Any] | None = None
    ):
        self.message = message or self.default_message
        self.status_code = status_code or self.status_code
        self.details = details or {}
        self.error_id = str(uuid.uuid4())
        super().__init__(self.message)


class ValidationError(APIError):
    """Exception raised for validation errors."""
    
    status_code: int = 400
    error_type: str = "validation_error"
    default_message: str = "Invalid input data."


class AuthenticationError(APIError):
    """Exception raised for authentication errors."""
    
    status_code: int = 401
    error_type: str = "authentication_error"
    default_message: str = "Authentication failed."


class AuthorizationError(APIError):
    """Exception raised for authorization errors."""
    
    status_code: int = 403
    error_type: str = "authorization_error"
    default_message: str = "You don't have permission to access this resource."


class ResourceNotFoundError(APIError):
    """Exception raised when a requested resource is not found."""
    
    status_code: int = 404
    error_type: str = "resource_not_found"
    default_message: str = "The requested resource was not found."


class ErrorResponse(BaseModel):
    """Standardized error response format.
    
    Includes both the 'message' field for our custom format and 'detail' field for
    compatibility with FastAPI standard error responses.
    """
    
    error_id: str
    error_type: str
    message: str
    detail: str | None = None  # For compatibility with FastAPI standard error responses
    status_code: int = 500
    details: dict[str, Any] | None = None
    
    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        """Override model_dump to ensure detail field is set from message if not explicitly provided."""
        data = super().model_dump(**kwargs)
        # Ensure detail is populated from message if not set
        if data.get('detail') is None and data.get('message') is not None:
            data['detail'] = data['message']
        return data


def sanitize_error_message(message: str) -> str:
    """
    Sanitize error messages to prevent PHI exposure.
    
    This function should be extended with specific sanitization rules
    based on the types of PHI that could potentially be exposed.
    
    Args:
        message: The original error message
        
    Returns:
        A sanitized version of the message
    """
    # Current implementation is basic - will expand with pattern matching
    # to detect and remove potential PHI patterns in future sprints
    
    # Don't expose detailed database errors, SQL errors, etc.
    if any(term in message.lower() for term in ['sql', 'database', 'query', 'constraint']):
        return "A data access error occurred. Please contact support."
    
    # Mask potential PHI in errors (simple initial implementation)
    # In a full implementation, we would use regex patterns to identify and mask PHI
    if any(term in message.lower() for term in ['patient', 'name', 'ssn', 'social', 'birth', 'address', 'email', 'phone']):
        return "An error occurred while processing sensitive data. Please contact support."
    
    # Return the original message if no specific sanitization rules apply
    return message


def register_exception_handlers(app: FastAPI, audit_logger: IAuditLogger) -> None:
    """
    Register all exception handlers with the FastAPI application.
    
    Args:
        app: The FastAPI application instance
        audit_logger: The audit logger implementation
    """
    
    @app.exception_handler(APIError)
    async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
        """Handle custom API errors."""
        sanitized_message = sanitize_error_message(exc.message)
        
        # Log the full error details internally
        await audit_logger.log_error(
            error_id=exc.error_id,
            error_type=exc.error_type,
            original_message=exc.message,
            sanitized_message=sanitized_message,
            status_code=exc.status_code,
            request_path=request.url.path,
            request_method=request.method,
            details=exc.details
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error_id=exc.error_id,
                message=sanitized_message,
                error_type=exc.error_type,
                status_code=exc.status_code
            ).dict()
        )
    
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Handle HTTP exceptions."""
        error_id = str(uuid.uuid4())
        sanitized_message = sanitize_error_message(exc.detail)
        error_type = f"http_{exc.status_code}"
        
        # Log the full error details internally
        await audit_logger.log_error(
            error_id=error_id,
            error_type=error_type,
            original_message=exc.detail,
            sanitized_message=sanitized_message,
            status_code=exc.status_code,
            request_path=request.url.path,
            request_method=request.method,
            details={}
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error_id=error_id,
                message=sanitized_message,
                error_type=error_type,
                status_code=exc.status_code
            ).dict()
        )
    
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle any unhandled exceptions."""
        error_id = str(uuid.uuid4())
        sanitized_message = "An internal server error occurred."
        error_type = "internal_error"
        
        # Log the full error details internally
        await audit_logger.log_error(
            error_id=error_id,
            error_type=error_type,
            original_message=str(exc),
            sanitized_message=sanitized_message,
            status_code=500,
            request_path=request.url.path,
            request_method=request.method,
            details={"traceback": str(exc.__traceback__)}
        )
        
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error_id=error_id,
                message=sanitized_message,
                error_type=error_type,
                status_code=500
            ).dict()
        )