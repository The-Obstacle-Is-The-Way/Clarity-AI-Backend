# API Security

## Overview

This document outlines the security implementation for the Clarity AI Backend APIs, focusing on HIPAA compliance, authentication, authorization, rate limiting, and secure data handling. The API security architecture follows clean design principles to ensure proper separation of concerns while maintaining robust protection mechanisms.

## JWT-Based Authentication

The Clarity AI Backend uses JSON Web Tokens (JWT) for stateless authentication with these key features:

1. **Token Generation**: Secure tokens created with user context upon login
2. **Payload Security**: Token payloads contain minimal, non-PHI identifiers 
3. **Token Validation**: Every protected endpoint verifies token validity
4. **Blacklisting**: Invalidated tokens are tracked for immediate access revocation
5. **Automatic Expiration**: Short-lived tokens enforce session timeouts

### JWT Service Interface

The JWT service follows a clean architecture interface design:

```python
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.domain.interfaces.token_repository import ITokenRepository

class JWTService:
    """
    Service for JWT token generation, validation, and management.
    
    This service adheres to HIPAA security requirements for authentication
    and authorization, including:
    - Secure token generation with appropriate expiration
    - Token validation and verification
    - Token blacklisting to enforce logout
    - Audit logging of token-related activities
    """

    def __init__(
        self,
        token_repo: ITokenRepository,
        blacklist_repo: ITokenBlacklistRepository,
        audit_logger: IAuditLogger
    ):
        """Initialize the JWT service."""
        
    def create_access_token(
        self, 
        user_id: str,
        email: str,
        role: str,
        permissions: list[str],
        session_id: str
    ) -> tuple[str, int]:
        """Create a new access token for a user."""
        
    def create_refresh_token(
        self, 
        user_id: str,
        email: str,
        session_id: str
    ) -> str:
        """Create a new refresh token for a user."""
        
    def validate_token(self, token: str, token_type: str = "access") -> dict[str, Any]:
        """Validate a JWT token and return its payload."""
        
    async def blacklist_token(self, token: str, user_id: str | None = None) -> None:
        """Add a token to the blacklist."""
        
    async def blacklist_session_tokens(self, session_id: str, user_id: str | None = None) -> None:
        """Blacklist all tokens for a session."""
```

### Token Lifecycle Management

The token lifecycle is carefully managed to maintain security:

1. **Token Creation**: Tokens contain unique JTI (JWT ID) and session binding
2. **Short Expiration**: Access tokens expire in minutes, refresh tokens in days
3. **Signature Verification**: Tokens are verified using HMAC-SHA256
4. **Blacklist Check**: Tokens are checked against blacklist before each use
5. **Audit Trail**: All token operations are logged for compliance

## Role-Based Access Control (RBAC)

The system implements a comprehensive role-based access control model:

```python
from enum import Enum
from typing import List, Dict, Set

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
    
    def __init__(self, role_permissions: Dict[UserRole, Set[str]]):
        """
        Initialize with role-permission mappings.
        
        Args:
            role_permissions: Dictionary mapping roles to permission sets
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

### Permission-Based Endpoint Protection

Endpoints are protected using permission decorators:

```python
from functools import wraps
from fastapi import Depends, HTTPException, status
from app.domain.entities.user import User
from app.presentation.api.dependencies.auth import get_current_user
from app.infrastructure.di.container import get_rbac_handler

def requires_permission(permission: str):
    """
    Decorator to protect routes with permission requirements.
    
    Args:
        permission: Required permission name
        
    Returns:
        Dependency function checking permission
    """
    def permission_dependency(current_user: User = Depends(get_current_user)):
        rbac_handler = get_rbac_handler()
        if not rbac_handler.has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return permission_dependency
```

## API Rate Limiting

The API implements rate limiting to prevent abuse and ensure availability:

```python
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.interfaces.services.rate_limiter_interface import IRateLimiterService
from app.domain.exceptions.rate_limit_exceptions import RateLimitExceededException

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
            
        except RateLimitExceededException as e:
            # Return rate limit exceeded response
            return Response(
                content={"detail": "Rate limit exceeded"},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json"
            )
```

## PHI Protection Middleware

The system includes specialized middleware to protect PHI in accordance with HIPAA:

```python
class PHIMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce HIPAA PHI handling requirements.
    
    This middleware:
    1. Prevents PHI from appearing in URLs (query params, path params)
    2. Logs all PHI access attempts for audit purposes
    3. Ensures proper error handling for PHI-related operations
    4. Sanitizes responses to prevent accidental PHI leakage
    """
    
    def __init__(
        self, 
        app: ASGIApp,
        phi_patterns: list[Pattern] | None = None,
        exempt_paths: set[str] | None = None
    ):
        """
        Initialize PHI middleware with patterns to detect and paths to exempt.
        
        Args:
            app: The ASGI application
            phi_patterns: Regular expression patterns to detect PHI
            exempt_paths: Paths exempt from PHI checks (e.g., auth endpoints)
        """
        super().__init__(app)
        self.phi_patterns = phi_patterns or [
            # Social Security Number patterns
            re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),
            # Medical Record Number patterns (various formats)
            re.compile(r"\bMRN[-:]?\d{6,10}\b", re.IGNORECASE),
            # Email patterns
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            # Date of birth patterns
            re.compile(r"\b(0[1-9]|1[0-2])[-/.](0[1-9]|[12]\d|3[01])[-/.](19|20)\d{2}\b"),
            # Common patient identifiers
            re.compile(r"\bPATIENT[-_]?ID[:=]?\d+\b", re.IGNORECASE),
        ]
        self.exempt_paths = exempt_paths or {
            "/api/v1/auth/token",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/docs",
            "/redoc",
            "/openapi.json",
        }
        
        # Get encryption service for HIPAA compliance
        container = get_container()
        try:
            self.encryption_service = container.get(IEncryptionService)
        except KeyError:
            # Create encryption service if not available
            self.encryption_service = BaseEncryptionService()
            container.register(IEncryptionService, self.encryption_service)
```

### PHI Protection Features

The PHI middleware provides several critical safeguards:

1. **URL Pattern Detection**: Regexp patterns detect common PHI formats in URLs
2. **Request Interception**: Blocks requests containing PHI in URLs
3. **Response Sanitization**: Removes PHI from error messages and responses
4. **Audit Logging**: Records all PHI access attempts for compliance
5. **Path Exemptions**: Allows specific non-PHI paths to bypass checks

## Request Validation

### Pydantic Model Validation

All request data is validated using Pydantic models to ensure data integrity:

```python
class PatientCreate(BaseModel):
    """Schema for creating a new patient."""
    
    first_name: str
    last_name: str
    date_of_birth: date
    gender: str
    email: EmailStr | None = None
    phone: str | None = None
    address: str | None = None
    
    @validator("date_of_birth")
    def validate_birth_date(cls, v):
        """Validate that birth date is not in the future."""
        if v > date.today():
            raise ValueError("Birth date cannot be in the future")
        return v
    
    @validator("gender")
    def validate_gender(cls, v):
        """Validate gender field."""
        allowed_values = ["male", "female", "other", "prefer_not_to_say"]
        if v.lower() not in allowed_values:
            raise ValueError(f"Gender must be one of: {', '.join(allowed_values)}")
        return v.lower()
```

### Input Sanitization

The system employs multiple layers of input sanitization:

1. **Type Validation**: Ensure input data matches expected types
2. **Value Constraints**: Apply business rules to validate input values
3. **SQL Injection Prevention**: All database queries use parameterized queries
4. **Cross-Site Scripting Protection**: HTML/JS content is escaped in responses
5. **Special Character Filtering**: Potentially dangerous characters are escaped

## Security Headers

The API applies security headers to all responses via middleware:

```python
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "no-referrer"
        
        return response
```

## Audit Logging

All security-relevant actions are logged for HIPAA compliance:

```python
class AuditLoggerService(IAuditLogger):
    """
    Implementation of the audit logger interface.
    
    Logs security and PHI access events for HIPAA compliance.
    """
    
    def __init__(self, log_repository: IAuditLogRepository):
        """Initialize with log repository."""
        self._log_repository = log_repository
    
    async def log_security_event(
        self,
        event_type: str,
        user_id: str | None,
        description: str,
        severity: str = "INFO",
        metadata: dict[str, Any] | None = None
    ) -> None:
        """
        Log a security-related event.
        
        Args:
            event_type: Type of security event
            user_id: ID of the user who triggered the event
            description: Human-readable description
            severity: Event severity level
            metadata: Additional event data
        """
        # Create log entry
        log_entry = AuditLogEntry(
            timestamp=datetime.utcnow(),
            event_type=event_type,
            user_id=user_id,
            description=description,
            severity=severity,
            metadata=metadata or {}
        )
        
        # Store log entry
        await self._log_repository.create(log_entry)
```

## HIPAA Compliance Summary

The API security implementation addresses the following HIPAA requirements:

1. **Access Controls**: Authentication, authorization, role-based permissions
2. **Audit Controls**: Comprehensive logging of all PHI access and security events
3. **Integrity Controls**: Data validation, checksums, encryption
4. **Person or Entity Authentication**: Secure authentication with token blacklisting
5. **Transmission Security**: TLS encryption, secure headers, token security
6. **PHI Protection**: Middleware preventing PHI in URLs and responses

By implementing these security measures in accordance with clean architecture principles, the Clarity AI Backend maintains a high level of security while preserving maintainability and adherence to domain boundaries.
