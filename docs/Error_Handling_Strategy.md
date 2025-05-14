# Error Handling Strategy

## Overview

The Error Handling Strategy in the Clarity AI Backend provides a comprehensive and consistent approach to managing exceptions throughout the application. This strategy ensures proper error isolation, meaningful error messages, HIPAA compliance in error reporting, and appropriate error responses to clients. By implementing a unified exception hierarchy and standardized error handling patterns, the system maintains robustness and reliability while adhering to clean architecture principles.

## Domain-Driven Exception Hierarchy

The system implements a domain-driven exception hierarchy that supports clean architecture and separation of concerns:

```text
BaseException
├── DomainExceptions
│   ├── ValidationException
│   ├── BusinessRuleException
│   ├── EntityNotFoundException
│   └── DomainStateException
├── ApplicationExceptions
│   ├── ApplicationError
│   ├── ConfigurationError
│   └── InitializationError
├── InfrastructureExceptions
│   ├── DatabaseException
│   ├── ExternalServiceException
│   ├── CacheException
│   └── FileSystemException
├── SecurityExceptions
│   ├── AuthenticationException
│   ├── AuthorizationException
│   ├── TokenException
│   └── HIPAAComplianceException
└── PresentationExceptions
    ├── APIException
    ├── ValidationException
    ├── RateLimitException
    └── ContentNegotiationException
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

## Layer-Specific Exceptions

Following clean architecture principles, each layer has its own exceptions that don't leak implementation details to other layers:

### Domain Layer Exceptions

```python
class ValidationException(BaseException):
    """Exception raised for domain validation errors."""

    def __init__(
        self,
        message: str = "Validation error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "VALIDATION_ERROR",
    ):
        super().__init__(message=message, detail=detail, code=code)


class EntityNotFoundException(BaseException):
    """Exception raised when a domain entity cannot be found."""

    def __init__(
        self,
        message: str = "Entity not found",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "ENTITY_NOT_FOUND",
    ):
        super().__init__(message=message, detail=detail, code=code)
```

### Application Layer Exceptions

```python
class ApplicationError(BaseException):
    """Base exception for application-level errors."""

    def __init__(
        self,
        message: str = "Application error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "APPLICATION_ERROR",
    ):
        super().__init__(message=message, detail=detail, code=code)


class UseCaseExecutionError(ApplicationError):
    """Exception raised when a use case execution fails."""

    def __init__(
        self,
        message: str = "Use case execution failed",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "USE_CASE_EXECUTION_ERROR",
    ):
        super().__init__(message=message, detail=detail, code=code)
```

### Infrastructure Layer Exceptions

```python
class DatabaseException(BaseException):
    """Exception raised for database-related errors."""

    def __init__(
        self,
        message: str = "Database error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "DATABASE_ERROR",
        original_exception: Exception | None = None,
    ):
        self.original_exception = original_exception
        super().__init__(message=message, detail=detail, code=code)


class ExternalServiceException(BaseException):
    """Exception raised for errors interacting with external services."""

    def __init__(
        self,
        message: str = "External service error",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "EXTERNAL_SERVICE_ERROR",
        service_name: str | None = None,
    ):
        self.service_name = service_name
        super().__init__(message=message, detail=detail, code=code)
```

### Security Exceptions

```python
class AuthenticationException(BaseException):
    """Exception raised for authentication failures."""

    def __init__(
        self,
        message: str = "Authentication failed",
        detail: str | list[str] | dict[str, Any] | None = None,
        code: str = "AUTHENTICATION_ERROR",
    ):
        super().__init__(message=message, detail=detail, code=code)


class HIPAAComplianceException(BaseException):
    """Exception raised for HIPAA compliance violations."""
    
    def __init__(
        self, 
        message: str = "HIPAA compliance violation",
        detail: str | list[str] | dict[str, Any] | None = None,
        violation_type: str | None = None,
        code: str = "HIPAA_COMPLIANCE_ERROR",
    ):
        self.violation_type = violation_type
        super().__init__(message=message, detail=detail, code=code)
```

## Clean Architecture Implementation

The error handling strategy aligns with clean architecture principles in several key ways:

### 1. Domain-First Exceptions

Domain layer exceptions represent business rule violations and domain invariants:

```python
# app/domain/models/patient.py
class Patient:
    def update_medical_record(self, record: MedicalRecord) -> None:
        """Update a patient's medical record following domain rules."""
        
        # Domain validation
        if not self.is_active:
            raise DomainStateException("Cannot update records for inactive patients")
            
        # Business rule validation
        if record.date > datetime.now():
            raise BusinessRuleException("Medical record date cannot be in the future")
        
        # Update record
        self._medical_records.append(record)
```

### 2. Proper Exception Translation

When crossing architectural boundaries, exceptions are translated to appropriate types for the layer:

```python
# app/infrastructure/repositories/sqlalchemy/patient_repository.py
class SQLAlchemyPatientRepository(IPatientRepository):
    async def get_by_id(self, patient_id: UUID) -> Patient:
        """Get a patient by ID."""
        try:
            result = await self.session.execute(
                select(PatientModel).where(PatientModel.id == patient_id)
            )
            patient_model = result.scalar_one_or_none()
            
            if not patient_model:
                # Translate to domain exception
                raise EntityNotFoundException(f"Patient with ID {patient_id} not found")
                
            return self._map_to_domain(patient_model)
            
        except SQLAlchemyError as e:
            # Translate infrastructure exception while preserving context
            raise DatabaseException(
                message="Database error while retrieving patient",
                detail=str(e),
                original_exception=e
            )
```

### 3. Clean Separation Between Layers

Exception handling maintains clean separation between architectural layers:

```python
# app/application/services/patient_service.py
class PatientService(IPatientService):
    async def update_patient_record(self, patient_id: UUID, record_data: dict) -> None:
        """Update a patient's medical record."""
        try:
            # Get patient from repository
            patient = await self.patient_repository.get_by_id(patient_id)
            
            # Create domain object
            record = MedicalRecord.create_from_dict(record_data)
            
            # Execute domain logic with domain exceptions
            patient.update_medical_record(record)
            
            # Save changes
            await self.patient_repository.save(patient)
            
        except EntityNotFoundException:
            # Pass domain exceptions through
            raise
            
        except DatabaseException as e:
            # Log infrastructure error but expose domain-friendly message
            self.logger.error(f"Database error: {str(e)}", exc_info=True)
            raise ApplicationError(
                message="Failed to update patient record",
                code="UPDATE_RECORD_FAILED"
            )
```

### 4. HIPAA-Compliant Error Handling

Error handling ensures no PHI is leaked in error messages:

```python
# app/presentation/api/error_handlers.py
@app.exception_handler(EntityNotFoundException)
async def entity_not_found_handler(request: Request, exc: EntityNotFoundException) -> JSONResponse:
    """Handle entity not found errors."""
    # Sanitize error message to remove any PHI
    original_message = str(exc)
    sanitized_message = "The requested resource was not found"
    
    # Log original error with proper PHI protection
    logger.info(f"EntityNotFoundException: {original_message}")
    
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": sanitized_message, "code": exc.code}
    )
```

## Error Handling Patterns

The system implements several standardized error handling patterns:

### 1. Try-Except-Log-Translate Pattern

```python
try:
    # Attempt operation
    result = await repository.fetch_data(id)
    return result
except EntityNotFoundException as e:
    # Domain exceptions pass through with minimal processing
    logger.info(f"Entity not found: {e}")
    raise
except DatabaseException as e:
    # Infrastructure exceptions are logged and translated
    logger.error(f"Database error: {e}", exc_info=True)
    raise ApplicationError(
        message="Unable to retrieve data",
        detail="A storage error occurred",
        code="DATA_RETRIEVAL_ERROR"
    )
except Exception as e:
    # Unexpected exceptions are logged and mapped to generic errors
    logger.critical(f"Unexpected error: {e}", exc_info=True)
    raise ApplicationError(message="An unexpected error occurred")
```

### 2. Result Objects for Expected Failures

For operations where "failure" is an expected outcome, Result objects are used instead of exceptions:

```python
class Result:
    """
    Result object for operations that may fail in expected ways.
    
    This avoids using exceptions for control flow in normal business processes.
    """
    
    def __init__(
        self, 
        success: bool, 
        value: Any = None, 
        error: str | None = None,
        error_code: str | None = None
    ):
        self.success = success
        self.value = value
        self.error = error
        self.error_code = error_code
    
    @classmethod
    def ok(cls, value: Any = None) -> 'Result':
        """Create a successful result."""
        return cls(success=True, value=value)
    
    @classmethod
    def fail(cls, error: str, error_code: str | None = None) -> 'Result':
        """Create a failed result."""
        return cls(success=False, error=error, error_code=error_code)
    
    def __bool__(self) -> bool:
        """Allow using the result in boolean contexts."""
        return self.success
```

Usage:

```python
# Example service method
async def validate_patient_eligibility(patient_id: UUID) -> Result:
    """
    Validate if a patient is eligible for treatment.
    
    Returns a Result object rather than raising exceptions for
    business rule validation failures.
    """
    patient = await self.patient_repository.get_by_id(patient_id)
    
    if not patient:
        return Result.fail(
            error="Patient not found",
            error_code="PATIENT_NOT_FOUND"
        )
    
    if patient.status != "active":
        return Result.fail(
            error="Patient is not active",
            error_code="PATIENT_INACTIVE"
        )
        
    if patient.has_insurance_coverage():
        return Result.ok(True)
    else:
        return Result.fail(
            error="Patient lacks insurance coverage",
            error_code="NO_INSURANCE"
        )
```

### 3. Global Exception Handlers in FastAPI

FastAPI's exception handler mechanism is used for centralized error handling:

```python
def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers."""
    
    @app.exception_handler(ValidationException)
    async def validation_exception_handler(request: Request, exc: ValidationException) -> JSONResponse:
        """Handle validation exceptions."""
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": exc.message, "errors": exc.detail, "code": exc.code}
        )
    
    @app.exception_handler(EntityNotFoundException)
    async def entity_not_found_exception_handler(request: Request, exc: EntityNotFoundException) -> JSONResponse:
        """Handle entity not found exceptions."""
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Resource not found", "code": exc.code}
        )
    
    @app.exception_handler(AuthenticationException)
    async def authentication_exception_handler(request: Request, exc: AuthenticationException) -> JSONResponse:
        """Handle authentication exceptions."""
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": exc.message, "code": exc.code}
        )
    
    @app.exception_handler(AuthorizationException)
    async def authorization_exception_handler(request: Request, exc: AuthorizationException) -> JSONResponse:
        """Handle authorization exceptions."""
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": exc.message, "code": exc.code}
        )
    
    @app.exception_handler(HIPAAComplianceException)
    async def hipaa_compliance_exception_handler(request: Request, exc: HIPAAComplianceException) -> JSONResponse:
        """Handle HIPAA compliance violations."""
        # Log the violation for compliance tracking
        logger.warning(
            f"HIPAA compliance violation: {exc.message}",
            extra={"violation_type": exc.violation_type}
        )
        
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Security policy violation", "code": exc.code}
        )
    
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle any unhandled exceptions."""
        # Generate error ID for tracking
        error_id = str(uuid.uuid4())
        
        # Log the exception with error ID
        logger.error(
            f"Unhandled exception [{error_id}]: {str(exc)}",
            exc_info=True
        )
        
        # Return sanitized response with error ID for reference
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An unexpected error occurred",
                "code": "INTERNAL_SERVER_ERROR",
                "error_id": error_id
            }
        )
```

### 4. Unit of Work Pattern with Error Handling

For operations that require transactional integrity, a Unit of Work pattern with error handling is used:

```python
async def create_patient_with_medical_history(self, patient_data: dict, medical_records: list[dict]) -> Patient:
    """Create a new patient with medical history in a single transaction."""
    
    async with self.uow:
        try:
            # Create patient
            patient = Patient.create_from_dict(patient_data)
            
            # Add medical records
            for record_data in medical_records:
                record = MedicalRecord.create_from_dict(record_data)
                patient.add_medical_record(record)
            
            # Persist in repository
            await self.uow.patient_repository.add(patient)
            
            # Commit transaction
            await self.uow.commit()
            
            return patient
            
        except ValidationException:
            # Domain validation errors should roll back and rethrow
            await self.uow.rollback()
            raise
            
        except Exception as e:
            # Any other errors should roll back and log
            await self.uow.rollback()
            logger.error(f"Error creating patient with medical history: {e}", exc_info=True)
            raise ApplicationError(
                message="Failed to create patient record",
                detail="An error occurred while saving patient data"
            )
```

## HIPAA-Compliant Error Handling

Special attention is given to HIPAA compliance in error handling:

### 1. PHI Sanitization in Errors

```python
class PHIErrorSanitizer:
    """Sanitize error messages to prevent PHI leakage."""
    
    def __init__(self):
        """Initialize with PHI detection patterns."""
        # Patterns that might contain PHI
        self._phi_patterns = [
            re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),  # SSN
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # Email
            re.compile(r"\b(0[1-9]|1[0-2])[-/.](0[1-9]|[12]\d|3[01])[-/.](19|20)\d{2}\b"),  # DOB
        ]
    
    def sanitize_error(self, error_message: str) -> str:
        """Remove potential PHI from error messages."""
        sanitized = error_message
        
        # Replace potential PHI with redacted text
        for pattern in self._phi_patterns:
            sanitized = pattern.sub("[REDACTED]", sanitized)
            
        # Replace common field names with generic descriptions
        sanitized = re.sub(r"(first_name|last_name):\s*['\"]\w+['\"]", r"\1: [REDACTED]", sanitized)
        
        return sanitized
```

### 2. Safe Error Responses

```python
def create_safe_error_response(exception: Exception, include_details: bool = False) -> dict:
    """
    Create a safe error response without exposing sensitive information.
    
    Args:
        exception: The exception that occurred
        include_details: Whether to include sanitized details
        
    Returns:
        A dictionary with safe error information
    """
    sanitizer = PHIErrorSanitizer()
    
    # Basic safe response
    response = {
        "error": type(exception).__name__,
        "message": sanitizer.sanitize_error(str(exception))
    }
    
    # Add sanitized details if requested
    if include_details and hasattr(exception, "detail") and exception.detail:
        if isinstance(exception.detail, str):
            response["detail"] = sanitizer.sanitize_error(exception.detail)
        elif isinstance(exception.detail, list):
            response["detail"] = [
                sanitizer.sanitize_error(item) if isinstance(item, str) else item
                for item in exception.detail
            ]
        elif isinstance(exception.detail, dict):
            response["detail"] = {
                k: sanitizer.sanitize_error(v) if isinstance(v, str) else v
                for k, v in exception.detail.items()
            }
    
    # Add error code if available
    if hasattr(exception, "code") and exception.code:
        response["code"] = exception.code
    
    return response
```

## Monitoring and Alerting

The error handling system integrates with monitoring and alerting:

```python
class AlertingErrorHandler:
    """Error handler that triggers alerts for critical errors."""
    
    def __init__(self, alert_service: IAlertService, threshold: int = 5):
        self.alert_service = alert_service
        self.error_counts = {}  # Track error counts
        self.threshold = threshold  # Alert threshold
    
    async def handle_error(self, error: Exception, context: dict | None = None) -> None:
        """
        Handle an error and trigger alerts if necessary.
        
        Args:
            error: The exception that occurred
            context: Additional context information
        """
        # Categorize the error
        error_type = type(error).__name__
        
        # Increment error count
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        # Check if we should alert
        if self.error_counts[error_type] >= self.threshold:
            # Reset count to avoid repeated alerts
            self.error_counts[error_type] = 0
            
            # Send alert
            await self.alert_service.send_alert(
                alert_type="frequent_errors",
                severity="high",
                message=f"Frequent errors of type {error_type}",
                details={
                    "error_type": error_type,
                    "count": self.threshold,
                    "latest_error": str(error),
                    "context": context
                }
            )
```

## Testing Error Handling

The error handling strategy includes comprehensive testing:

```python
@pytest.mark.asyncio
async def test_entity_not_found_exception_handler():
    """Test handling of EntityNotFoundException."""
    # Create test app with exception handlers
    app = FastAPI()
    register_exception_handlers(app)
    
    @app.get("/test-not-found")
    async def test_not_found():
        raise EntityNotFoundException("Test patient not found")
    
    # Create test client
    client = TestClient(app)
    
    # Test the endpoint
    response = client.get("/test-not-found")
    
    # Verify response
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Resource not found",
        "code": "ENTITY_NOT_FOUND"
    }
    
    # Verify no PHI in response (original message had "patient" but sanitized)
    assert "patient" not in response.text


@pytest.mark.asyncio
async def test_hipaa_compliance_exception_handler():
    """Test handling of HIPAAComplianceException."""
    # Create test app with exception handlers
    app = FastAPI()
    register_exception_handlers(app)
    
    @app.get("/test-hipaa-violation")
    async def test_hipaa_violation():
        raise HIPAAComplianceException(
            message="PHI found in URL: 123-45-6789",
            violation_type="phi_in_url"
        )
    
    # Create test client
    client = TestClient(app)
    
    # Test the endpoint
    response = client.get("/test-hipaa-violation")
    
    # Verify response
    assert response.status_code == 403
    assert response.json() == {
        "detail": "Security policy violation", 
        "code": "HIPAA_COMPLIANCE_ERROR"
    }
    
    # Verify no PHI in response (original had SSN but sanitized)
    assert "123-45-6789" not in response.text
```

## Conclusion

The error handling strategy in the Clarity AI Backend provides a comprehensive approach to managing exceptions while adhering to clean architecture principles. By properly categorizing, isolating, translating, and handling exceptions at each architectural layer, the system maintains robustness and reliability while ensuring HIPAA compliance in error reporting.
