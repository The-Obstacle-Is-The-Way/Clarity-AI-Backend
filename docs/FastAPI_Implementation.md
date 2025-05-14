# FastAPI Implementation Guide

## Clean Architecture Overview

The Clarity AI Backend is built on Clean Architecture principles, ensuring separation of concerns and maintainability:

- **Domain Layer** (`app/domain`): Core business entities, interfaces, and rules independent of external frameworks
- **Application Layer** (`app/application`): Use cases, DTOs, and application services that orchestrate domain objects
- **Infrastructure Layer** (`app/infrastructure`): External adapters, repository implementations, and framework integrations
- **Presentation Layer** (`app/presentation`): API endpoints, request/response models, and middleware

## Application Factory Pattern

The application uses a factory pattern (`app_factory.py`) to create and configure the FastAPI application instance, which:

1. Initializes logging configuration
2. Sets up database connections and session factories
3. Configures middleware
4. Registers exception handlers
5. Includes API routers
6. Initializes third-party services (Sentry, Redis)

```python
def create_application(
    settings_override: Optional[Settings] = None,
    include_test_routers: bool = False,
    jwt_service_override: JWTServiceInterface | None = None,
    skip_auth_middleware: bool = False,
    disable_audit_middleware: bool = False
) -> FastAPI:
    # Application configuration
```

## Dependency Injection

The codebase implements dependency injection in three main ways:

1. **Container-based DI** (`app/infrastructure/di/container.py`): Centralized registration and resolution of services
2. **FastAPI Dependency System**: Used for endpoint-specific dependencies
3. **Application State**: Essential services stored on `app.state` for middleware access

Example dependency injection in endpoints:
```python
@router.get("/patients/{patient_id}")
async def get_patient(
    patient_id: UUID,
    patient_service: PatientService = Depends(get_patient_service)
):
    return await patient_service.get_patient(patient_id)
```

## Middleware Stack

The application uses multiple middleware components for request processing:

1. **RequestIdMiddleware**: Adds unique request IDs for tracking
2. **LoggingMiddleware**: Records request/response activity with HIPAA compliance
3. **SecurityHeadersMiddleware**: Adds secure headers to HTTP responses
4. **AuthenticationMiddleware**: Validates JWT tokens and sets user context
5. **RateLimitingMiddleware**: Prevents abuse through request limiting
6. **AuditLogMiddleware**: Records user activity for compliance

The middleware stack is configured in `app_factory.py` and processes requests in the specified order.

## Exception Handling

Custom exception handlers provide consistent error responses and prevent PHI leakage:

1. **RequestValidationError**: Handles Pydantic validation failures
2. **HTTPException**: Handles FastAPI HTTP exceptions
3. **SQLAlchemyError**: Handles database errors securely
4. **Generic Exception Handler**: Catches unhandled exceptions

All error handlers return sanitized JSON responses with appropriate status codes while logging detailed information for troubleshooting.

## API Versioning

The API uses a path-based versioning strategy with routes organized under `/api/v1/`:

- Endpoints are modular and grouped by domain area
- Routes are registered in `app/presentation/api/v1/api_router.py`
- Version-specific schemas are in `app/presentation/api/v1/schemas/`

This approach allows for future versioning with minimal disruption.

## Database Access

Database access follows the Repository pattern:

1. SQLAlchemy models in `app/infrastructure/persistence/sqlalchemy/models/`
2. Repository interfaces in `app/domain/repositories/`
3. Repository implementations in `app/infrastructure/persistence/sqlalchemy/repositories/`

The application uses SQLAlchemy's async capabilities with connection pooling and parameterized queries for security.

## Authentication Flow

1. Client authenticates via `/api/v1/auth/login` 
2. JWT access and refresh tokens are issued
3. **AuthenticationMiddleware** validates tokens on subsequent requests
4. User context is added to request state
5. Refresh tokens are used to obtain new access tokens

JWT tokens are signed, contain claims like issuer and audience, and have configurable expiration times.

## Security Features

The application implements multiple security measures:

1. **Input Validation**: Pydantic models validate all input data
2. **Parameter Binding**: SQL queries use parameterized statements
3. **Output Sanitization**: PHI is filtered from error responses
4. **TLS Configuration**: HTTPS-only in production
5. **Rate Limiting**: Prevents brute force and DoS attacks
6. **Audit Logging**: Records all security-relevant actions

## HIPAA Compliance

1. **PHI Encryption**: Sensitive data is encrypted at rest
2. **Audit Trail**: All PHI access is logged
3. **Authentication**: Role-based access control enforced
4. **Session Management**: Timeouts for inactive sessions
5. **Transmission Security**: Data encrypted in transit
6. **Error Handling**: No PHI in error messages
7. **Sanitized Logs**: PHI redacted from application logs

## Testing Support

The application includes testing infrastructure in `app/tests/`:

1. **Test Fixtures**: Database, client, and authentication helpers
2. **Mock Services**: In-memory implementations for testing
3. **Test Configuration**: Environment-specific settings

The `conftest.py` file configures the test environment with in-memory databases and disabled middleware when appropriate. 