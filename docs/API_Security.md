# API Security

## Overview

This document outlines the security implementation for the Clarity AI Backend APIs, focusing on HIPAA compliance, authentication, authorization, rate limiting, and secure data handling. The API security architecture follows clean design principles to ensure proper separation of concerns while maintaining robust protection mechanisms.

## Authentication System

### JWT-Based Authentication

The Clarity AI Backend uses JSON Web Tokens (JWT) for stateless authentication:

```python
# Core interface definition
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional

class IJWTService(ABC):
    """Interface for JWT token handling."""
    
    @abstractmethod
    async def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[int] = None) -> str:
        """
        Create a new JWT access token.
        
        Args:
            data: Payload data to include in token
            expires_delta: Optional custom expiration time in seconds
            
        Returns:
            JWT token string
        """
        pass
    
    @abstractmethod
    async def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.
        
        Args:
            token: JWT token to decode
            
        Returns:
            Token payload
            
        Raises:
            JWTError: If token is invalid or expired
        """
        pass
    
    @abstractmethod
    async def blacklist_token(self, token: str) -> None:
        """
        Add a token to the blacklist.
        
        Args:
            token: JWT token to blacklist
        """
        pass
    
    @abstractmethod
    async def is_token_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token: JWT token to check
            
        Returns:
            True if token is blacklisted
        """
        pass
```

### Token Lifecycle Management

1. **Token Generation**: JWT tokens are created upon successful authentication
2. **Payload Security**: Tokens contain minimal user information with no PHI
3. **Token Validation**: Every protected endpoint verifies token validity
4. **Token Blacklisting**: Invalidated tokens are tracked in Redis
5. **Automatic Expiration**: Short-lived tokens enforce session timeouts

## Authorization Framework

### Role-Based Access Control (RBAC)

```python
from enum import Enum
from typing import List

class UserRole(str, Enum):
    """User roles for authorization."""
    ADMIN = "admin"
    CLINICIAN = "clinician"
    RESEARCHER = "researcher"
    PATIENT = "patient"

class RBACHandler:
    """
    Handles role-based access control for API endpoints.
    
    Maps roles to permissions and verifies user access rights.
    """
    
    def __init__(self, role_permissions: Dict[UserRole, List[str]]):
        """
        Initialize with role-permission mappings.
        
        Args:
            role_permissions: Dictionary mapping roles to permission lists
        """
        self._role_permissions = role_permissions
    
    def has_permission(self, user_role: UserRole, required_permission: str) -> bool:
        """
        Check if a role has a specific permission.
        
        Args:
            user_role: User's role
            required_permission: Permission to check
            
        Returns:
            True if user has permission
        """
        if user_role not in self._role_permissions:
            return False
            
        return required_permission in self._role_permissions[user_role]
```

### Permission Decorators

```python
from functools import wraps
from fastapi import Depends, HTTPException, status
from app.core.domain.entities import User
from app.presentation.api.dependencies.auth import get_current_user

def requires_permission(permission: str):
    """
    Decorator to protect routes with permission requirements.
    
    Args:
        permission: Required permission name
        
    Returns:
        Dependency function checking permission
    """
    def permission_dependency(current_user: User = Depends(get_current_user)):
        if not rbac_handler.has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return permission_dependency
```

## API Rate Limiting

### Rate Limiting Middleware

```python
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.interfaces.services import IRateLimiterService
from app.core.domain.errors import RateLimitExceededError

class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for API rate limiting.
    
    Protects API endpoints from abuse by limiting request frequency.
    """
    
    def __init__(self, app, rate_limiter: IRateLimiterService):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI application
            rate_limiter: Rate limiter service implementation
        """
        super().__init__(app)
        self._rate_limiter = rate_limiter
    
    async def dispatch(self, request: Request, call_next):
        """
        Process the request with rate limiting.
        
        Args:
            request: Incoming request
            call_next: Next middleware or endpoint handler
            
        Returns:
            Response from next handler
            
        Raises:
            HTTPException: If rate limit exceeded
        """
        # Get client identifier (IP or authenticated user ID)
        client_id = self._get_client_id(request)
        
        # Apply rate limiting
        try:
            await self._rate_limiter.check_rate_limit(client_id)
            
            # Process request normally
            response = await call_next(request)
            
            # Add rate limit headers
            remaining = await self._rate_limiter.get_remaining(client_id)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            
            return response
            
        except RateLimitExceededError as e:
            # Return rate limit exceeded response
            return Response(
                content={"detail": "Rate limit exceeded"},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json"
            )
```

## HIPAA-Compliant Request and Response Handling

### Request Validation

1. **Schema Validation**: All requests validated against Pydantic models
2. **Input Sanitization**: Special characters and potential injection vectors filtered
3. **Type Safety**: Strong typing enforced for all API inputs

### PHI Protection

1. **PHI Masking Middleware**: Automatically detects and masks PHI in logs and error messages
2. **Request ID Tracking**: Unique identifiers for all requests without PHI
3. **Data Minimization**: Only essential data transmitted in requests/responses

```python
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import re
import uuid

class PHIProtectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware for protecting PHI in requests and responses.
    
    Automatically sanitizes PHI patterns in responses and logs.
    """
    
    def __init__(self, app):
        """Initialize middleware."""
        super().__init__(app)
        
        # Patterns to detect potential PHI
        self._phi_patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{9}\b",  # 9-digit numeric identifiers
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\(\d{3}\)\s*\d{3}[-. ]?\d{4}\b",  # Phone (xxx) xxx-xxxx
            r"\b\d{3}[-. ]?\d{3}[-. ]?\d{4}\b",  # Phone xxx-xxx-xxxx
        ]
        self._phi_regex = re.compile("|".join(self._phi_patterns))
    
    async def dispatch(self, request: Request, call_next):
        """Process the request with PHI protection."""
        # Assign request ID for tracking without PHI
        request.state.request_id = str(uuid.uuid4())
        
        # Process the request
        response = await call_next(request)
        
        # Check if response contains PHI and sanitize if needed
        if response.headers.get("content-type") == "application/json":
            content = await response.body()
            content_str = content.decode("utf-8")
            
            # Sanitize PHI in response
            sanitized = self._sanitize_phi(content_str)
            
            if sanitized != content_str:
                # Create new response with sanitized content
                return Response(
                    content=sanitized,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type="application/json"
                )
        
        return response
    
    def _sanitize_phi(self, content: str) -> str:
        """Replace PHI with masked values."""
        return self._phi_regex.sub("[REDACTED]", content)
```

## Secure Headers Middleware

```python
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to responses.
    
    Implements recommended security headers for web applications.
    """
    
    async def dispatch(self, request: Request, call_next):
        """Add security headers to response."""
        response = await call_next(request)
        
        # Add security headers
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        
        return response
```

## Request ID and Audit Trail

```python
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import uuid
from app.core.interfaces.services import IAuditLogger

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware for tracking requests with unique IDs.
    
    Assigns a unique identifier to each request for tracking
    without using PHI.
    """
    
    def __init__(self, app, audit_logger: IAuditLogger):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI application
            audit_logger: Audit logging service
        """
        super().__init__(app)
        self._audit_logger = audit_logger
    
    async def dispatch(self, request: Request, call_next):
        """Process the request with tracking ID."""
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Add to response headers
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        # Log the request (sanitized)
        await self._audit_logger.log_api_request(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            user_id=getattr(request.state, "user_id", None),
            duration_ms=getattr(request.state, "duration_ms", None)
        )
        
        return response
```

## Error Handling

```python
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from app.core.domain.errors import (
    ApplicationError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    RateLimitExceededError
)
from app.core.interfaces.services import IErrorSanitizer

def configure_exception_handlers(app: FastAPI, error_sanitizer: IErrorSanitizer):
    """
    Configure global exception handlers.
    
    Args:
        app: FastAPI application
        error_sanitizer: Service for sanitizing errors
    """
    
    @app.exception_handler(AuthenticationError)
    async def auth_error_handler(request: Request, exc: AuthenticationError):
        """Handle authentication errors."""
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Authentication failed"}
        )
    
    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(request: Request, exc: AuthorizationError):
        """Handle authorization errors."""
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Not authorized"}
        )
    
    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError):
        """Handle validation errors."""
        # Sanitize error messages to remove any PHI
        sanitized_errors = error_sanitizer.sanitize_validation_errors(exc.errors)
        
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": sanitized_errors}
        )
    
    @app.exception_handler(NotFoundError)
    async def not_found_error_handler(request: Request, exc: NotFoundError):
        """Handle not found errors."""
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Resource not found"}
        )
    
    @app.exception_handler(RateLimitExceededError)
    async def rate_limit_error_handler(request: Request, exc: RateLimitExceededError):
        """Handle rate limit errors."""
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded"}
        )
    
    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception):
        """Handle all other errors."""
        # Sanitize to remove any PHI from error message
        safe_message = error_sanitizer.sanitize_error_message(str(exc))
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"}
        )
```

## Implementation Status

### Current Status

- ✅ JWT authentication fully implemented
- ✅ Role-based authorization system complete
- ✅ Request validation with Pydantic models
- ✅ Security headers middleware implemented
- ✅ PHI protection in logs and responses
- ✅ Rate limiting middleware
- ✅ Request ID tracking

### Architectural Gaps

- 🔄 Token blacklisting needs Redis implementation
- 🔄 Fine-grained permission system could be enhanced
- 🔄 Additional PHI detection patterns needed

## HIPAA Compliance Checklist

| Security Requirement | Status | Implementation |
|----------------------|--------|----------------|
| Authentication (§164.312(d)) | ✅ | JWT tokens with proper validation |
| Authorization (§164.312(a)(1)) | ✅ | Role-based access control |
| Audit Controls (§164.312(b)) | ✅ | Request logging with sanitization |
| Integrity (§164.312(c)(1)) | ✅ | Data validation, encryption |
| Transmission Security (§164.312(e)(1)) | ✅ | TLS, secure headers |
| Access Control (§164.312(a)(1)) | ✅ | User-based permissions |
| Automatic Logoff (§164.312(a)(2)(iii)) | ✅ | Token expiration |
| Unique User Identification (§164.312(a)(2)(i)) | ✅ | User authentication system |

## Secure API Patterns

### Protected Endpoint Pattern

```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.domain.entities import User
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.api.dependencies.services import get_patient_service
from app.core.interfaces.services import IPatientService
from app.presentation.schemas.patient import PatientResponse

router = APIRouter()

@router.get(
    "/patients/{patient_id}",
    response_model=PatientResponse,
    summary="Get patient details",
    description="Retrieve detailed information about a specific patient"
)
async def get_patient(
    patient_id: str,
    current_user: User = Depends(get_current_user),
    patient_service: IPatientService = Depends(get_patient_service)
):
    """
    Retrieve patient information with proper authorization checks.
    
    This endpoint demonstrates the secure pattern for accessing PHI:
    1. Authentication via JWT token
    2. Authorization check for appropriate role
    3. Audit logging of the access
    4. Response validation and sanitization
    """
    # Check if user has permission to view this patient
    if current_user.role != UserRole.ADMIN and current_user.id != patient_id:
        # Check if clinician has relationship with patient
        if current_user.role == UserRole.CLINICIAN:
            has_access = await patient_service.clinician_has_access(
                current_user.id, patient_id
            )
            if not has_access:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to access this patient"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this patient"
            )
    
    # Retrieve patient data
    patient = await patient_service.get_by_id(patient_id)
    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )
    
    # Return validated response
    return PatientResponse.from_domain_entity(patient)
```
