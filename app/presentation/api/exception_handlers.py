"""
Exception handlers for the FastAPI application.

This module defines exception handlers that integrate with the core error handling
utilities to ensure proper HIPAA-compliant error responses and audit logging.
"""

import logging
import traceback
import uuid
from collections.abc import Awaitable, Callable
from typing import TypeVar, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_422_UNPROCESSABLE_ENTITY,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.core.exceptions.auth_exceptions import (
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
    TokenExpiredError,
)
from app.core.exceptions.validation import ValidationError
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.core.utils.error_handling import (
    APIError,
    ErrorResponse,
    sanitize_error_message,
)
from app.presentation.api.dependencies.audit_logger import get_audit_logger

logger = logging.getLogger(__name__)


# Define generic exception type for better type annotations
ExcType = TypeVar('ExcType', bound=Exception)

# Type alias for exception handlers to improve type safety
ExceptionHandler = Callable[[Request, ExcType], Awaitable[Response]]

def register_exception_handlers(app: FastAPI) -> None:
    """
    Register all exception handlers with the FastAPI application.
    
    This function registers handlers for standard exceptions as well as
    custom application exceptions to ensure consistent error responses
    and proper audit logging of errors.
    
    Args:
        app: FastAPI application instance
    """
    # Register handlers with appropriate type casts to satisfy mypy
    # Register handlers for standard exceptions
    app.add_exception_handler(
        StarletteHTTPException, 
        cast(Callable[[Request, Exception], Awaitable[Response]], http_exception_handler)
    )
    app.add_exception_handler(
        RequestValidationError, 
        cast(Callable[[Request, Exception], Awaitable[Response]], validation_exception_handler)
    )
    
    # Register handlers for application-specific exceptions
    app.add_exception_handler(
        APIError, 
        cast(Callable[[Request, Exception], Awaitable[Response]], api_error_handler)
    )
    
    # Register handlers for specific authentication/authorization errors
    app.add_exception_handler(
        AuthenticationError, 
        cast(Callable[[Request, Exception], Awaitable[Response]], authentication_error_handler)
    )
    app.add_exception_handler(
        AuthorizationError, 
        cast(Callable[[Request, Exception], Awaitable[Response]], authorization_error_handler)
    )
    app.add_exception_handler(
        InvalidTokenError, 
        cast(Callable[[Request, Exception], Awaitable[Response]], invalid_token_handler)
    )
    app.add_exception_handler(
        TokenExpiredError, 
        cast(Callable[[Request, Exception], Awaitable[Response]], token_expired_handler)
    )
    
    # Register handler for all other unhandled exceptions
    app.add_exception_handler(
        Exception, 
        cast(Callable[[Request, Exception], Awaitable[Response]], unhandled_exception_handler)
    )
    
    logger.info("HIPAA-compliant exception handlers registered")


def _get_audit_logger() -> IAuditLogger:
    # Get the audit logger implementation
    return get_audit_logger()


async def _log_error(
    request: Request,
    exception: Exception,
    status_code: int,
    error_id: str,
    error_type: str,
) -> None:
    """
    Log an error to the audit logger with proper PHI sanitization.
    
    Args:
        request: The request that caused the exception
        exception: The exception that was raised
        status_code: HTTP status code for the response
        error_id: Unique ID for the error (for correlation)
        error_type: Type of error for categorization
    """
    try:
        # Get audit logger
        audit_logger = _get_audit_logger()
        
        # Sanitize exception details
        original_message = str(exception)
        sanitized_message = sanitize_error_message(original_message)
        
        # Create sanitized details
        details = {
            "error_id": error_id,
            "error_type": error_type,
            "request_path": str(request.url.path),
            "request_method": request.method,
        }
        
        # Audit log the error - call directly without await since log_error is not async
        audit_logger.log_error(
            error_id=error_id,
            error_type=error_type,
            original_message=original_message,
            sanitized_message=sanitized_message,
            status_code=status_code,
            request_path=str(request.url.path),
            request_method=request.method,
            details=details
        )
    except Exception as e:
        # Fallback to standard logging if audit logging fails
        logger.error(
            f"Error during audit logging: {e}. Original error: {error_type} - {error_id}",
            exc_info=True
        )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Handle standard HTTP exceptions with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Log the error
    await _log_error(
        request=request,
        exception=exc,
        status_code=exc.status_code,
        error_id=error_id,
        error_type="http_exception"
    )
    
    # Create sanitized response
    content = ErrorResponse(
        error_id=error_id,
        error_type="http_exception",
        message=sanitize_error_message(str(exc.detail)),
        status_code=exc.status_code
    ).model_dump()
    
    return JSONResponse(status_code=exc.status_code, content=content)


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle request validation errors with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Log the error
    await _log_error(
        request=request,
        exception=exc,
        status_code=HTTP_422_UNPROCESSABLE_ENTITY,
        error_id=error_id,
        error_type="validation_error"
    )
    
    # Sanitize validation errors
    sanitized_errors = []
    for error in exc.errors():
        error_copy = dict(error)
        if "msg" in error_copy:
            error_copy["msg"] = sanitize_error_message(error_copy["msg"])
        sanitized_errors.append(error_copy)
    
    # Create sanitized response
    content = ErrorResponse(
        error_id=error_id,
        error_type="validation_error",
        message="Request validation failed",
        details={"errors": sanitized_errors},
        status_code=HTTP_422_UNPROCESSABLE_ENTITY
    ).model_dump()
    
    return JSONResponse(status_code=HTTP_422_UNPROCESSABLE_ENTITY, content=content)


async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handle application-specific API errors with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Determine status code based on error type
    status_code = HTTP_500_INTERNAL_SERVER_ERROR
    if hasattr(exc, "status_code"):
        status_code = exc.status_code
    
    # Log the error
    await _log_error(
        request=request,
        exception=exc,
        status_code=status_code,
        error_id=error_id,
        error_type=exc.__class__.__name__
    )
    
    # Create sanitized response
    content = ErrorResponse(
        error_id=error_id,
        error_type=exc.__class__.__name__,
        message=sanitize_error_message(str(exc)),
        status_code=status_code
    ).model_dump()
    
    return JSONResponse(status_code=status_code, content=content)


async def application_validation_error_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    """Handle application-specific validation errors with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Log the error
    await _log_error(
        request=request,
        exception=exc,
        status_code=HTTP_400_BAD_REQUEST,
        error_id=error_id,
        error_type="application_validation_error"
    )
    
    # For validation errors, we want to preserve the original message
    # since validation error messages don't contain PHI and are needed by clients
    error_message = str(exc)
    
    # Create response with original validation error message
    content = ErrorResponse(
        error_id=error_id,
        error_type="application_validation_error",
        message=error_message,
        detail=error_message  # Ensure detail field has the validation message too
    ).model_dump()
    content["status_code"] = HTTP_400_BAD_REQUEST
    
    return JSONResponse(status_code=HTTP_400_BAD_REQUEST, content=content)


async def authentication_error_handler(
    request: Request, exc: AuthenticationError
) -> JSONResponse:
    """Handle authentication errors with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Log the error
    await _log_error(
        request=request,
        exception=exc,
        status_code=HTTP_401_UNAUTHORIZED,
        error_id=error_id,
        error_type="authentication_error"
    )
    
    # Create sanitized response
    content = ErrorResponse(
        error_id=error_id,
        error_type="authentication_error",
        message=sanitize_error_message(str(exc))
    ).model_dump()
    content["status_code"] = HTTP_401_UNAUTHORIZED
    
    return JSONResponse(status_code=HTTP_401_UNAUTHORIZED, content=content)


async def authorization_error_handler(
    request: Request, exc: AuthorizationError
) -> JSONResponse:
    """Handle authorization errors with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Log the error
    await _log_error(
        request=request,
        exception=exc,
        status_code=HTTP_403_FORBIDDEN,
        error_id=error_id,
        error_type="authorization_error"
    )
    
    # Create sanitized response
    content = ErrorResponse(
        error_id=error_id,
        error_type="authorization_error",
        message=sanitize_error_message(str(exc))
    ).model_dump()
    content["status_code"] = HTTP_403_FORBIDDEN
    
    return JSONResponse(status_code=HTTP_403_FORBIDDEN, content=content)


async def invalid_token_handler(
    request: Request, exc: InvalidTokenError
) -> JSONResponse:
    """Handle invalid token errors with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Log the error
    await _log_error(
        request=request,
        exception=exc,
        status_code=HTTP_401_UNAUTHORIZED,
        error_id=error_id,
        error_type="invalid_token_error"
    )
    
    # Create sanitized response
    content = ErrorResponse(
        error_id=error_id,
        error_type="invalid_token_error",
        message=sanitize_error_message(str(exc))
    ).model_dump()
    content["status_code"] = HTTP_401_UNAUTHORIZED
    
    return JSONResponse(status_code=HTTP_401_UNAUTHORIZED, content=content)


async def token_expired_handler(
    request: Request, exc: TokenExpiredError
) -> JSONResponse:
    """Handle token expired errors with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Log the error
    await _log_error(
        request=request,
        exception=exc,
        status_code=HTTP_401_UNAUTHORIZED,
        error_id=error_id,
        error_type="token_expired_error"
    )
    
    # Create sanitized response
    content = ErrorResponse(
        error_id=error_id,
        error_type="token_expired_error",
        message=sanitize_error_message(str(exc))
    ).model_dump()
    content["status_code"] = HTTP_401_UNAUTHORIZED
    
    return JSONResponse(status_code=HTTP_401_UNAUTHORIZED, content=content)


async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Handle all unhandled exceptions with audit logging."""
    error_id = str(uuid.uuid4())
    
    # Format traceback for logging (but not for response)
    tb_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.error(f"Unhandled exception: {exc}\n{tb_str}")
    
    # Log the error with audit logger
    await _log_error(
        request=request,
        exception=exc,
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
        error_id=error_id,
        error_type="unhandled_exception"
    )
    
    # Create sanitized response - for security, don't expose details of internal errors
    content = ErrorResponse(
        error_id=error_id,
        error_type="unhandled_exception",
        message="An internal server error occurred"
    ).model_dump()
    content["status_code"] = HTTP_500_INTERNAL_SERVER_ERROR
    
    return JSONResponse(
        status_code=HTTP_500_INTERNAL_SERVER_ERROR, 
        content=content
    )
