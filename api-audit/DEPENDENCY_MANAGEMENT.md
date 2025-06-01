# Dependency Management Issues

## Overview

This document analyzes the dependency injection patterns in the Clarity AI Backend API, identifying inconsistencies and architectural violations that impact maintainability, testability, and adherence to clean architecture principles.

## Current Dependency Injection Problems

### 1. Location of Dependency Providers

| Issue | Example | Architectural Impact |
|-------|---------|----------------------|
| Dependencies defined in route files | `get_rule_repository` in `biometric_alert_rules.py` | Violates separation of concerns |
| Inconsistent provider directory structure | Some in `dependencies/`, others in `v1/dependencies/` | Creates confusion for developers |
| Redundant dependency definitions | Multiple variants of similar providers across files | Leads to code duplication |

### 2. Direct Infrastructure Dependencies

Several API route files import concrete implementations directly from the infrastructure layer, violating clean architecture principles:

```python
# Direct infrastructure import (violates clean architecture)
from app.infrastructure.logging.audit_logger import audit_log_phi_access

# Proper interface import (follows clean architecture)
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface
```

This pattern makes it difficult to:
- Replace implementations for testing
- Swap infrastructure components
- Maintain clear separation between layers

### 3. Inconsistent Dependency Function Signatures

Dependency provider functions have inconsistent signatures across the codebase:

```python
# Different return type annotations
def get_patient_service(db_session: AsyncSession = Depends(get_db)) -> PatientService: ...
def get_rule_repository(db_session) -> BiometricAlertRuleRepository: ...  # Missing type annotation

# Inconsistent parameter naming
def get_service(db: AsyncSession = Depends(get_db)): ...
def get_other_service(db_session: AsyncSession = Depends(get_db)): ...

# Inconsistent use of async
async def get_async_dependency(...): ...
def get_sync_dependency(...): ...  # Should be async for consistent pattern
```

### 4. Missing Interface Dependencies

Many services are injected without proper interface definitions:

| Service | Issue | Required Interface |
|---------|-------|-------------------|
| JWTService | Using concrete class instead of interface | IJWTService |
| TokenBlacklist | Missing interface definition | ITokenBlacklistRepository |
| AuditLogger | Direct infrastructure import | IAuditLogger |
| RateLimitingMiddleware | Missing implementation | IRateLimiter |

### 5. Redis Dependency Management

Redis client (`app.state.redis`) and pool (`app.state.redis_pool`) are initialized directly in the `lifespan` manager in `app_factory.py` and stored in `app.state`. This approach:

- Violates dependency injection principles
- Makes testing difficult
- Creates tight coupling between FastAPI and Redis implementation

## Impact on Testing

These dependency management issues directly impact test capabilities:

1. **Test Mocking Challenges**: Inconsistent dependencies make it difficult to create standardized mocks
2. **Brittle Tests**: Direct infrastructure dependencies lead to brittle tests that break with implementation changes
3. **Test Isolation**: Lack of proper interface-based injection makes it hard to isolate components for testing

## Impact on HIPAA Compliance

Proper dependency management is crucial for HIPAA compliance:

1. **Audit Logging**: Inconsistent injection of audit loggers risks missing critical security events
2. **Error Handling**: Proper PHI sanitization depends on consistent error handling through dependencies
3. **Access Control**: Authentication/authorization depends on properly injected security services

## Recommendations

### 1. Standardize Dependency Provider Locations

Move all dependency providers to a consistent location:

```
app/presentation/api/dependencies/
├── common/
│   ├── database.py
│   ├── security.py
│   └── logging.py
├── services/
│   ├── patient_service.py
│   └── alert_service.py
└── repositories/
    ├── user_repository.py
    └── alert_repository.py
```

### 2. Implement Missing Interfaces

Define interfaces for all services in the core layer:

- `ITokenBlacklistRepository`
- `IAuditLogger`
- `IPasswordHandler`
- `IRedisService`

### 3. Use Consistent Dependency Function Signatures

Standardize all dependency provider functions:

```python
# Standardized pattern for repository dependencies
async def get_user_repository(
    db_session: AsyncSession = Depends(get_db_session)
) -> IUserRepository:
    """Get user repository implementation."""
    return SQLAlchemyUserRepository(db_session)

# Standardized pattern for service dependencies
async def get_alert_service(
    alert_repo: IAlertRepository = Depends(get_alert_repository),
    user_repo: IUserRepository = Depends(get_user_repository)
) -> IAlertService:
    """Get alert service implementation."""
    return AlertService(alert_repo, user_repo)
```

### 4. Refactor Redis Access

1. Define `IRedisService` interface in `app.core.interfaces`
2. Implement `RedisService` in `app.infrastructure` using `app.state.redis`
3. Create `get_redis_service(request: Request) -> IRedisService` dependency provider
4. Update code using `app.state.redis` to depend on `IRedisService` via FastAPI's `Depends`

### 5. Update Tests

Revise test fixtures to align with the standardized dependency injection pattern:

```python
@pytest_asyncio.fixture
async def mock_alert_service():
    service = AsyncMock(spec=IAlertService)
    # Configure mock behavior
    return service

@pytest_asyncio.fixture
def app_with_dependencies(
    mock_alert_service: AsyncMock,
    mock_user_repository: AsyncMock
):
    app = FastAPI()
    app.dependency_overrides[get_alert_service] = lambda: mock_alert_service
    app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
    return app
```

## Implementation Priority

1. Define missing interfaces in core layer
2. Standardize dependency provider location and signatures
3. Update route files to use the standardized dependencies
4. Refactor tests to use the new dependency structure

This approach will resolve architectural violations while maintaining backward compatibility and ensuring HIPAA compliance.

See [Standardization Plan](./STANDARDIZATION_PLAN.md) for implementation details.
