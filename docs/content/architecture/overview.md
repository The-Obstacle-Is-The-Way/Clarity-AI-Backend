# Architecture Overview

## Clean Architecture Implementation

Clarity AI implements a rigorous clean architecture approach with separation of concerns across four distinct layers:

```
┌───────────────────┐      ┌───────────────────┐
│  Presentation     │─▶───▶│  Application      │
│ (FastAPI + Schemas│      │ (Use‑Cases)       │
│  + Middleware)    │      └───────────────────┘
└───────────────────┘              │
        ▲                          ▼
        │                  ┌───────────────────┐
┌───────────────────┐      │  Domain           │
│ Infrastructure    │◀────▶│ (Entities)        │
│ (DB, ML, Cache,   │      └───────────────────┘
│  Messaging, Auth) │
└───────────────────┘
```

### Architectural Layers

#### 1. Domain Layer

Contains business entities and core business rules:

- **Entities**: Core business models (`app/domain/entities/`)
- **Value Objects**: Immutable domain objects (`app/domain/value_objects/`)
- **Domain Services**: Pure business logic (`app/domain/services/`)
- **Domain Exceptions**: Business rule violations (`app/domain/exceptions/`)
- **Repository Interfaces**: Data access abstractions (`app/core/interfaces/repositories/`)

#### 2. Application Layer

Coordinates domain objects to execute use cases:

- **Use Cases**: Business workflows (`app/application/use_cases/`)
- **Application Services**: Orchestration services (`app/application/services/`)
- **DTOs**: Data transfer objects (`app/application/dtos/`)

#### 3. Infrastructure Layer

Provides technical capabilities and interface implementations:

- **Repositories**: Database implementations (`app/infrastructure/persistence/repositories/`)
- **External Services**: Third-party integrations (`app/infrastructure/services/`)
- **Security**: Authentication and authorization (`app/infrastructure/security/`)
- **Logging**: Audit and application logging (`app/infrastructure/logging/`)

#### 4. Presentation Layer

Handles HTTP requests and responses:

- **API Routes**: REST endpoint definitions (`app/presentation/api/v1/endpoints/`)
- **Request/Response Models**: Data validation (`app/presentation/schemas/`)
- **Middleware**: Request processing pipeline (`app/presentation/middleware/`)
- **Dependencies**: Dependency injection (`app/presentation/api/dependencies/`)

## Dependency Injection

The codebase uses FastAPI's dependency injection system to maintain proper architectural boundaries:

```python
# Dependency definition
def get_user_repository(
    db_session: AsyncSession = Depends(get_db_session)
) -> IUserRepository:
    return SQLAlchemyUserRepository(db_session)

# Usage in endpoint
@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    user_repository: IUserRepository = Depends(get_user_repository)
):
    return await user_repository.get_by_id(user_id)
```

## Design Patterns

### Repository Pattern

Abstracts data access operations:

```python
class IUserRepository(Protocol):
    async def get_by_id(self, id: UUID) -> Optional[User]:
        ...

class SQLAlchemyUserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session
        
    async def get_by_id(self, id: UUID) -> Optional[User]:
        # Implementation
```

### Factory Pattern

Creates complex objects:

```python
def create_alert_service(
    alert_repository: IAlertRepository,
    notification_service: INotificationService
) -> AlertService:
    return AlertService(
        repository=alert_repository,
        notification_service=notification_service
    )
```

### Strategy Pattern

Defines a family of algorithms:

```python
class NotificationStrategy(Protocol):
    async def send_notification(self, alert: Alert) -> bool:
        ...

class EmailNotificationStrategy:
    async def send_notification(self, alert: Alert) -> bool:
        # Implementation
```

### Decorator Pattern

Adds responsibilities to objects dynamically:

```python
def audit_log_decorator(func):
    @functools.wraps(func)
    async def wrapper(self, *args, **kwargs):
        # Log access before operation
        result = await func(self, *args, **kwargs)
        # Log result after operation
        return result
    return wrapper
```

## SOLID Principles Application

1. **Single Responsibility**: Each class has one reason to change
2. **Open/Closed**: Entities are open for extension, closed for modification
3. **Liskov Substitution**: Interfaces can be substituted with implementations
4. **Interface Segregation**: Specific interfaces over general-purpose ones
5. **Dependency Inversion**: High-level modules depend on abstractions

## System Monitoring

The backend includes monitoring for system health and HIPAA compliance:

1. **Performance Metrics**: Request latency, database performance, ML model execution time
2. **Security Monitoring**: Authentication attempts, access patterns, PHI access logging
3. **Data Quality Metrics**: Biometric data completeness, digital twin model accuracy
4. **Operational Health**: Service availability, database connections, background tasks