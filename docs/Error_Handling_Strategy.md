# Error Handling Strategy

## Overview

The Error Handling Strategy in the Clarity AI Backend provides a comprehensive and consistent approach to managing exceptions throughout the application. This strategy ensures proper error isolation, meaningful error messages, HIPAA compliance in error reporting, and appropriate error responses to clients. By implementing a unified exception hierarchy and standardized error handling patterns, the system maintains robustness and reliability while adhering to clean architecture principles.

## Exception Hierarchy

The system implements a carefully designed exception hierarchy that supports clean architecture and domain-driven design:

```text
BaseException
├── ValidationException
├── ResourceNotFoundException/ResourceNotFoundError
│   └── EntityNotFoundError
├── AuthenticationException
├── AuthorizationException
├── BusinessRuleException
├── ConfigurationError/InvalidConfigurationError
├── ExternalServiceException
├── DatabaseException/PersistenceError
├── SecurityException
├── ApplicationError
├── InitializationError
└── HIPAAComplianceError
```

### Base Exception

At the root of the hierarchy is the `BaseException` class, which provides the foundational structure for all application exceptions:

```python
class BaseException(Exception):
    """
    Base exception for all application exceptions.

    Attributes:
        message: A human-readable error message
        detail: Additional information about the error
        code: An error code for machine processing
    """

    def __init__(
        self,
        message: str,
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str | None = None,
    ):
        self.message = message
        self.detail = detail
        self.code = code
        super().__init__(self.message)
```

This design provides several key advantages:

- **Structured Error Information**: All exceptions include a human-readable message, optional details, and an error code
- **Consistent Interface**: Standardized approach to creating and handling exceptions
- **Extensibility**: Easy to extend for domain-specific exceptions

## Domain-Specific Exceptions

The exception hierarchy includes specialized exceptions for different domains within the application:

### Validation Exceptions

```python
class ValidationException(BaseException):
    """Exception raised for validation errors."""

    def __init__(
        self,
        message: str = "Validation error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "VALIDATION_ERROR",
    ):
        super().__init__(message=message, detail=detail, code=code)
```

Used for input validation failures, schema validation errors, and constraint violations.

### Resource Exceptions

```python
class ResourceNotFoundException(BaseException):
    """Exception raised when a requested resource is not found."""

    def __init__(
        self,
        message: str = "Resource not found",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "RESOURCE_NOT_FOUND",
    ):
        super().__init__(message=message, detail=detail, code=code)
```

Used when requested resources (patients, digital twins, etc.) can't be found.

### Security Exceptions

```python
class SecurityException(BaseException):
    """Exception raised for security-related errors."""

    def __init__(
        self,
        message: str = "Security error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "SECURITY_ERROR",
    ):
        super().__init__(message=message, detail=detail, code=code)
```

Used for security violations, encryption failures, and other security-related errors.

### HIPAA Compliance Exceptions

```python
class HIPAAComplianceError(BaseException):
    """Exception raised for HIPAA compliance violations."""
    
    def __init__(
        self, 
        message: str = "HIPAA compliance violation",
        detail: str | list[str] | dict[str, Any] | None = None,
        violation_type: str | None = None,
        code: str = "HIPAA_COMPLIANCE_ERROR",
    ):
        super().__init__(message=message, detail=detail, code=code)
        self.violation_type = violation_type
```

Specialized for handling HIPAA compliance violations, providing context for the specific type of violation.

## Clean Architecture Implementation

The error handling strategy aligns with clean architecture principles in several key ways:

### Layer-Specific Exceptions

Each architectural layer has appropriate exception types:

1. **Domain Layer**: Business rule exceptions, entity validation errors
2. **Application Layer**: Use case validation, coordination errors
3. **Infrastructure Layer**: Database exceptions, external service errors
4. **Presentation Layer**: Input validation, response formatting errors

### Dependency Rules

Exceptions flow from inner to outer layers, respecting the dependency rule:

1. Inner layers define their own exceptions
2. Outer layers catch and translate exceptions when crossing boundaries
3. Domain exceptions never depend on infrastructure exceptions
4. Infrastructure errors are mapped to appropriate domain errors before propagating

### Centralized Definition

All core exceptions are defined in the `app/core/exceptions/base_exceptions.py` module, ensuring:

- Consistent error types across the application
- Single source of truth for exception handling
- Easier maintenance and extension

## Error Handling Patterns

The system implements several standardized error handling patterns:

### Try-Except-Map Pattern

```python
try:
    # Attempt operation
    result = await some_operation()
    return result
except ValidationError as e:
    # Map to appropriate HTTP response
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"message": str(e), "code": e.code, "details": e.detail}
    )
except ResourceNotFoundException as e:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"message": str(e), "code": e.code, "details": e.detail}
    )
except Exception as e:
    # Log unexpected errors
    logger.error(f"Unexpected error: {str(e)}", exc_info=True)
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"message": "An unexpected error occurred", "code": "INTERNAL_ERROR"}
    )
```

This pattern ensures:

- Known exceptions are mapped to appropriate responses
- Unexpected exceptions are caught, logged, and translated to generic errors
- PHI is never exposed in error messages

### Global Exception Handlers

FastAPI's exception handler mechanism is used for centralized error handling:

```python
@app.exception_handler(NovaBaseException)
async def base_exception_handler(request: Request, exc: NovaBaseException) -> JSONResponse:
    """Handle all application-specific exceptions."""
    status_code = 500
    
    # Map exception types to status codes
    if isinstance(exc, ValidationException):
        status_code = 400
    elif isinstance(exc, ResourceNotFoundException):
        status_code = 404
    elif isinstance(exc, AuthenticationException):
        status_code = 401
    elif isinstance(exc, AuthorizationException):
        status_code = 403
    
    # Sanitize any potential PHI from error details
    sanitized_detail = sanitize_error_details(exc.detail)
    
    # Log the error with appropriate level
    log_error(request, exc, status_code)
    
    # Return structured error response
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "type": exc.__class__.__name__,
                "message": str(exc),
                "code": exc.code,
                "detail": sanitized_detail
            }
        }
    )
```

### Unit of Work Pattern

For operations that require transactional integrity, a Unit of Work pattern with error handling is used:

```python
async def create_patient(self, patient_data: dict) -> Patient:
    """Create a new patient with transactional integrity."""
    async with self.uow:
        try:
            # Validate input
            if self._validate_patient_data(patient_data):
                # Create patient
                patient = await self.uow.patient_repository.create(patient_data)
                # Create initial alerts
                await self.uow.alert_repository.create_default_alerts(patient.id)
                # Commit transaction
                await self.uow.commit()
                return patient
        except Exception as e:
            # Rollback on any error
            await self.uow.rollback()
            # Translate to appropriate domain exception
            if isinstance(e, IntegrityError):
                raise BusinessRuleException(
                    message="Patient with this identifier already exists",
                    detail={"field": "patient_identifier"},
                    code="DUPLICATE_PATIENT"
                )
            # Re-raise other exceptions
            raise
```

This ensures:
- Transactional integrity with automatic rollback on errors
- Appropriate translation of infrastructure errors to domain exceptions
- Clean separation between technical and domain errors

## HIPAA Compliance in Error Handling

The error handling strategy implements several HIPAA compliance measures:

### PHI Sanitization

All error messages and details are processed to remove potential PHI:

```python
def sanitize_error_details(details: Any) -> Any:
    """Remove any potential PHI from error details."""
    if isinstance(details, str):
        return sanitize_phi_from_text(details)
    elif isinstance(details, dict):
        return {k: sanitize_error_details(v) for k, v in details.items()}
    elif isinstance(details, list):
        return [sanitize_error_details(item) for item in details]
    return details
```

### Audit Logging

Security and authentication errors are logged with appropriate context for audit purposes:

```python
def log_security_event(
    event_type: str,
    user_id: Optional[str],
    details: dict,
    success: bool,
    source_ip: Optional[str] = None
) -> None:
    """Log security events for audit purposes."""
    logger.info(
        f"SECURITY: {event_type}",
        extra={
            "event_type": event_type,
            "user_id": user_id,
            "details": details,
            "success": success,
            "source_ip": source_ip,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
```

### Error Exposure Control

Different levels of error detail are provided based on the environment and recipient:

1. **Development**: Full error details including stack traces
2. **Internal API**: Structured error information without sensitive details
3. **Public API**: Minimal information to prevent information disclosure

## Exception Handling in Asynchronous Operations

For asynchronous operations, special error handling patterns are implemented:

### Background Task Error Handling

```python
@router.post("/analyze")
async def analyze_patient_data(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks
):
    """Queue analysis as a background task with error handling."""
    task_id = str(uuid.uuid4())
    
    # Store initial status
    await state_store.set(f"task:{task_id}", {"status": "pending"})
    
    # Add task to background queue with error handler
    background_tasks.add_task(
        process_analysis_with_error_handling,
        task_id=task_id,
        patient_id=request.patient_id,
        analysis_type=request.analysis_type
    )
    
    return {"task_id": task_id, "status": "pending"}

async def process_analysis_with_error_handling(
    task_id: str,
    patient_id: str,
    analysis_type: str
) -> None:
    """Process analysis with comprehensive error handling."""
    try:
        # Update status to running
        await state_store.set(f"task:{task_id}", {"status": "running"})
        
        # Perform analysis
        result = await perform_analysis(patient_id, analysis_type)
        
        # Store success result
        await state_store.set(
            f"task:{task_id}",
            {
                "status": "completed",
                "result": result,
                "completed_at": datetime.utcnow().isoformat()
            }
        )
    except Exception as e:
        # Log error
        logger.error(
            f"Error in background task {task_id}: {str(e)}",
            exc_info=True,
            extra={"task_id": task_id, "patient_id": patient_id}
        )
        
        # Store error status (without exposing sensitive details)
        await state_store.set(
            f"task:{task_id}",
            {
                "status": "failed",
                "error": {"message": "Analysis failed", "code": "ANALYSIS_ERROR"},
                "failed_at": datetime.utcnow().isoformat()
            }
        )
```

### Event-Based Error Handling

For event-driven architectures, errors are handled through error events:

```python
try:
    # Process event
    await handle_event(event)
    # Publish success
    await event_bus.publish("event.processed", {"event_id": event.id})
except Exception as e:
    # Transform to error event
    error_event = {
        "original_event_id": event.id,
        "error_type": type(e).__name__,
        "error_message": str(e),
        "timestamp": datetime.utcnow().isoformat()
    }
    # Publish error event
    await event_bus.publish("event.processing.failed", error_event)
    # Maybe retry
    if is_retryable(e):
        await retry_queue.enqueue(event, delay=compute_backoff(event))
```

## Error Responses

API error responses follow a consistent structure:

```json
{
  "error": {
    "type": "ResourceNotFoundException",
    "message": "Patient with ID 12345 not found",
    "code": "PATIENT_NOT_FOUND",
    "detail": {
      "resource_type": "Patient",
      "resource_id": "12345"
    }
  }
}
```

This structure ensures:
- Machine-readable error classification (`type` and `code`)
- Human-readable explanation (`message`)
- Context for debugging and user feedback (`detail`)
- No exposure of sensitive information

## Testing Error Scenarios

The strategy includes comprehensive testing of error scenarios:

1. **Unit Tests**: Verify that functions raise appropriate exceptions
2. **Integration Tests**: Ensure error handling mechanisms work across component boundaries
3. **API Tests**: Validate that API endpoints return correct status codes and error structures
4. **Stress Tests**: Confirm that error handling remains robust under load

Example test case:

```python
@pytest.mark.asyncio
async def test_patient_not_found():
    """Test that appropriate exception is raised when patient not found."""
    # Arrange
    patient_id = str(uuid.uuid4())
    patient_service = PatientService(MockPatientRepository())
    
    # Act/Assert
    with pytest.raises(ResourceNotFoundException) as exc_info:
        await patient_service.get_patient(patient_id)
    
    # Verify exception details
    assert exc_info.value.code == "RESOURCE_NOT_FOUND"
    assert patient_id in str(exc_info.value)
```

## Best Practices

The error handling strategy follows these best practices:

1. **Don't Expose Implementation Details**: Error messages never reveal internal structures or stack traces
2. **Layer-Appropriate Exceptions**: Each layer handles and translates exceptions appropriate to its context
3. **HIPAA-Safe Error Messages**: All error messages are designed to prevent PHI exposure
4. **Comprehensive Logging**: Errors are logged with appropriate context for debugging and audit
5. **Graceful Degradation**: System components fail gracefully and maintain overall system stability

## Related Components

- **Logging System**: Captures and stores error information
- **Audit System**: Records security-relevant errors for compliance
- **Monitoring System**: Detects error patterns and alerts operations staff
- **Global Exception Handlers**: Centralize error response formatting
- **Input Validation**: Prevents many errors through early validation
