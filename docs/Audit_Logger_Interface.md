# Audit Logger Interface

## Overview

The Audit Logger Interface (`IAuditLogger`) is a cornerstone of the Clarity AI Backend's compliance and security architecture. This interface defines the contract for recording security-relevant events and access to Protected Health Information (PHI) to maintain HIPAA compliance and support security forensics.

## Architectural Significance

In a psychiatric digital twin platform subject to HIPAA regulations, comprehensive audit logging is mandatory. The `IAuditLogger` interface:

1. **Enforces Compliance**: Ensures all PHI access is recorded as required by HIPAA
2. **Enables Security Analysis**: Provides data necessary for detecting unauthorized access
3. **Supports Investigations**: Creates an immutable record of system interactions 
4. **Maintains Data Lineage**: Tracks who accessed what data and when

## Interface Definition

The `IAuditLogger` interface is defined in the core layer:

```python
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional, Union
from uuid import UUID

class IAuditLogger(ABC):
    """
    Interface for audit logging operations.
    
    This interface defines methods for recording security events and
    PHI access in compliance with HIPAA and security best practices.
    """
    
    @abstractmethod
    async def log_security_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        user_id: Optional[Union[str, UUID]] = None,
        source_ip: Optional[str] = None
    ) -> None:
        """
        Log a security-related event.
        
        Args:
            event_type: Category of security event (e.g., 'login_attempt', 'permission_change')
            details: Event-specific details (should not contain PHI)
            user_id: ID of the user initiating the event (if authenticated)
            source_ip: Source IP address of the request
        """
        pass
    
    @abstractmethod
    async def log_phi_access(
        self,
        resource_type: str,
        resource_id: Union[str, UUID],
        action: str,
        user_id: Union[str, UUID],
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None
    ) -> None:
        """
        Log access to Protected Health Information (PHI).
        
        Args:
            resource_type: Type of resource containing PHI (e.g., 'patient', 'medical_record')
            resource_id: Identifier of the specific resource
            action: Action performed ('view', 'create', 'update', 'delete')
            user_id: ID of the user accessing the PHI
            reason: Clinical or operational reason for access
            details: Additional context (should not contain PHI itself)
            source_ip: Source IP address of the request
        """
        pass
    
    @abstractmethod
    async def log_api_request(
        self,
        request_id: str,
        method: str,
        path: str,
        status_code: int,
        user_id: Optional[Union[str, UUID]] = None,
        source_ip: Optional[str] = None,
        duration_ms: Optional[float] = None
    ) -> None:
        """
        Log an API request for audit purposes.
        
        Args:
            request_id: Unique identifier for the request
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            status_code: HTTP response status code
            user_id: ID of the authenticated user (if any)
            source_ip: Source IP address of the request
            duration_ms: Request processing duration in milliseconds
        """
        pass
```

## Known Implementations

This interface has several implementations in the codebase:

1. **DatabaseAuditLogger**: Primary implementation that stores audit records in a database
2. **ConsoleAuditLogger**: Development implementation that logs to console
3. **MultiAuditLogger**: Composite implementation that delegates to multiple loggers
4. **MockAuditLogger**: Test implementation with event capture for assertions

## Usage Contexts

The Audit Logger is used throughout the system in several key contexts:

1. **Authentication flows**: Login attempts, password changes, etc.
2. **PHI access**: Recording all views of patient data
3. **API Middleware**: Automatic logging of all API requests
4. **Administrative actions**: User creation, permission changes

## Usage in API Middleware

The Audit Logger is integrated into the middleware stack for comprehensive request logging:

```python
class AuditLogMiddleware(BaseHTTPMiddleware):
    """Middleware for automatic audit logging of API requests."""
    
    def __init__(
        self,
        app: ASGIApp,
        audit_logger: IAuditLogger
    ):
        super().__init__(app)
        self._audit_logger = audit_logger
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        request_id = request.state.request_id
        
        # Process the request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
        # Get user ID if authenticated
        user_id = getattr(request.state, "user", {}).get("id", None)
        
        # Log the API request
        await self._audit_logger.log_api_request(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            user_id=user_id,
            source_ip=request.client.host,
            duration_ms=duration_ms
        )
        
        return response
```

## Dependency Injection

The Audit Logger is provided through FastAPI's dependency injection system:

```python
from fastapi import Depends
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.infrastructure.logging.audit_logger import DatabaseAuditLogger
from app.infrastructure.persistence.repositories.audit_log_repository import AuditLogRepository
from app.presentation.dependencies.database import get_session

async def get_audit_logger(
    session = Depends(get_session)
) -> IAuditLogger:
    """
    Dependency provider for Audit Logger.
    
    Args:
        session: Database session
    
    Returns:
        IAuditLogger implementation
    """
    repository = AuditLogRepository(session)
    return DatabaseAuditLogger(repository)
```

## Compliance Requirements

The Audit Logger implementation satisfies these HIPAA requirements:

1. **§164.308(a)(1)(ii)(D)**: Information system activity review
2. **§164.312(b)**: Audit controls to record and examine activity
3. **§164.308(a)(5)(ii)(C)**: Log-in monitoring
4. **§164.312(c)(2)**: Mechanism to authenticate that data hasn't been altered
5. **§164.316(b)(1)**: Records retention requirements

## Future Extensions

The next version of this interface should consider:

1. **Event Aggregation**: Methods for detecting patterns across events
2. **Real-time Alerting**: Capabilities to trigger alerts on suspicious activity 
3. **Exportable Formats**: Support for exporting audit logs in standard formats
