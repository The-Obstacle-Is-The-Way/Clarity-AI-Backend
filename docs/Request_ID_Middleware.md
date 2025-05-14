# Request ID Middleware

## Overview

The Request ID Middleware is a foundational component of the Clarity AI Backend's observability and security architecture. It assigns a unique identifier to each incoming request, enabling comprehensive request tracing, correlation of logs, and forensic audit capabilities required for HIPAA compliance.

## Architectural Significance

In a psychiatric digital twin platform with strict security and compliance requirements, request tracing is essential. The Request ID Middleware:

1. **Enables Comprehensive Tracing**: Correlates logs across all system components
2. **Supports HIPAA Audit Requirements**: Associates all database and PHI operations with specific requests
3. **Facilitates Debugging**: Makes it possible to isolate and track specific request flows
4. **Enhances Security Analysis**: Provides context for identifying suspicious access patterns

## Implementation

The `RequestIdMiddleware` is implemented as a Starlette middleware component:

```python
# app/presentation/middleware/request_id.py
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fastapi import FastAPI

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds a unique request ID to each incoming request.
    
    This middleware generates a UUID for each request and makes it available:
    1. As a request.state.request_id attribute
    2. As an X-Request-ID response header
    
    The middleware also preserves client-provided request IDs when present
    in the X-Request-ID header, enabling end-to-end tracing across systems.
    """
    
    def __init__(
        self,
        app: FastAPI,
        header_name: str = "X-Request-ID",
        *args,
        **kwargs
    ):
        """
        Initialize the Request ID middleware.
        
        Args:
            app: The FastAPI application
            header_name: The name of the header to use for request IDs
        """
        super().__init__(app)
        self.header_name = header_name
    
    async def dispatch(
        self,
        request: Request,
        call_next
    ) -> Response:
        """
        Process the request and add a unique request ID.
        
        Args:
            request: The incoming request
            call_next: The next middleware or route handler
            
        Returns:
            The response with an added request ID header
        """
        # Check if request already has an ID from the client
        request_id = request.headers.get(self.header_name)
        
        # If no ID provided or empty, generate a new one
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Store the request ID in request state for other middleware and handlers
        request.state.request_id = request_id
        
        # Process the request
        response = await call_next(request)
        
        # Add the request ID to the response headers
        response.headers[self.header_name] = request_id
        
        return response
```

## Integration in Application Factory

The Request ID Middleware is one of the first middleware components added in the application factory:

```python
# app/app_factory.py (excerpt)
def create_application(...) -> FastAPI:
    # ... (initial application setup)
    
    # Configure middleware - order matters!
    # Request ID must be first to ensure all subsequent middleware have access to it
    app.add_middleware(
        RequestIdMiddleware,
        header_name="X-Request-ID"
    )
    
    # Add other middleware components that depend on request_id
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(AuditLogMiddleware)
    
    # ... (remaining application setup)
```

## Usage Patterns

### Access Within Request Handlers

Access the request ID directly in endpoint functions:

```python
@router.get("/patients/{patient_id}")
async def get_patient(
    patient_id: UUID,
    request: Request,
    patient_service: PatientService = Depends(get_patient_service)
):
    """Get a single patient by ID."""
    # Access the request ID
    request_id = request.state.request_id
    
    # Log the request with its ID
    logger.info(f"Processing get_patient request {request_id} for patient {patient_id}")
    
    # Process the request
    patient = await patient_service.get_patient(patient_id)
    
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    return patient
```

### Integration with Structured Logging

The request ID should be included in all log messages:

```python
# app/core/logging_config.py
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "app.core.logging.JsonFormatter",
            "fmt_keys": {
                "level": "levelname",
                "message": "message",
                "timestamp": "timestamp",
                "logger": "name",
                "request_id": "request_id",  # Include request_id in all logs
                "module": "module",
                "function": "funcName",
                "line": "lineno",
            }
        },
        # ... other formatters
    },
    # ... handlers and loggers configuration
}
```

### Custom Logger Adapter

A custom logger adapter can automatically include the request ID:

```python
# app/core/logging/adapter.py
import logging
from contextvars import ContextVar
from typing import Optional

# Context variable to store request ID
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

class RequestIdAdapter(logging.LoggerAdapter):
    """
    Logger adapter that automatically includes the request ID in all log records.
    """
    
    def process(self, msg, kwargs):
        """Add request_id to the log record."""
        if "extra" not in kwargs:
            kwargs["extra"] = {}
        
        # Get request ID from context variable
        request_id = request_id_var.get()
        
        if request_id:
            kwargs["extra"]["request_id"] = request_id
        else:
            kwargs["extra"]["request_id"] = "no-request-id"
            
        return msg, kwargs
```

### Middleware Integration

The middleware can set the request ID in the context variable:

```python
# app/presentation/middleware/request_id.py (extended)
from app.core.logging.adapter import request_id_var

class RequestIdMiddleware(BaseHTTPMiddleware):
    # ... existing code ...
    
    async def dispatch(self, request: Request, call_next):
        # ... existing code to generate request_id ...
        
        # Store in request state
        request.state.request_id = request_id
        
        # Also set in the context variable for logging
        token = request_id_var.set(request_id)
        
        try:
            # Process the request
            response = await call_next(request)
            
            # Add the request ID to the response headers
            response.headers[self.header_name] = request_id
            
            return response
        finally:
            # Reset the context variable
            request_id_var.reset(token)
```

## HIPAA Compliance Considerations

The Request ID Middleware supports HIPAA compliance requirements in several ways:

1. **Access Tracking**: Every API request has a unique identifier for audit trails
2. **Activity Correlation**: PHI access logs can be linked to specific requests
3. **Forensic Investigation**: Security incidents can be traced across system components
4. **Non-Repudiation**: All actions are attributable to specific requests and users

## Testing Considerations

When testing with the Request ID Middleware:

1. **Middleware Order**: The Request ID Middleware must be added before other middleware
2. **Header Preservation**: Tests should verify request IDs are properly propagated
3. **Client-Provided IDs**: Tests should verify client-provided IDs are honored
4. **Log Correlation**: Tests should verify logs contain the correct request ID

Example test:

```python
async def test_request_id_generation_and_propagation(test_client):
    """Test that the middleware generates and propagates request IDs."""
    # Make a request without a request ID
    response = await test_client.get("/api/v1/health")
    
    # Verify the response has a request ID header
    assert "X-Request-ID" in response.headers
    request_id = response.headers["X-Request-ID"]
    assert uuid.UUID(request_id)  # Should be a valid UUID
    
    # Make a second request with the same ID
    response2 = await test_client.get(
        "/api/v1/health",
        headers={"X-Request-ID": request_id}
    )
    
    # Verify the same ID is returned
    assert response2.headers["X-Request-ID"] == request_id
```

## Implementation Challenges

Common challenges when implementing the Request ID Middleware:

1. **Distributed Tracing**: Ensuring IDs are propagated to external services
2. **Performance Impact**: Minimizing overhead for high-throughput applications
3. **ID Collisions**: Avoiding ID collisions in high-volume environments
4. **Asynchronous Processing**: Maintaining context in background tasks

## Conclusion

The Request ID Middleware is a foundational component that enables robust request tracing throughout the Clarity AI Backend. It provides the basis for comprehensive logging, audit trails, and security forensics required for HIPAA compliance in a psychiatric digital twin platform.

By implementing this middleware according to clean architecture principles and integrating it with the logging system, the application maintains a clear record of all requests and their outcomes, supporting both operational diagnostics and regulatory compliance requirements.
