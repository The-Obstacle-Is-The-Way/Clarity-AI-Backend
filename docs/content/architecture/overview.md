# Architecture Overview

## Clean Architecture Implementation

Clarity AI implements a rigorous clean architecture approach with separation of concerns across distinct layers:

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

## Architectural Layers

### 1. Domain Layer

The domain layer contains business entities and core business rules. In the Clarity AI codebase, domain entities are found in two locations:

- **Primary location**: `app/core/domain/entities/`
- **Secondary location**: `app/domain/entities/`

This layer also includes:

- **Value Objects**: Immutable domain objects (`app/domain/value_objects/`)
- **Domain Services**: Pure business logic (`app/domain/services/`)
- **Domain Exceptions**: Business rule violations (`app/domain/exceptions/`)
- **Repository Interfaces**: Data access abstractions (`app/core/interfaces/repositories/`)

### 2. Application Layer

Coordinates domain objects to execute use cases:

- **Use Cases**: Business workflows (`app/application/use_cases/`)
- **Application Services**: Orchestration services (`app/application/services/`)
- **DTOs**: Data transfer objects (`app/application/dtos/`)

### 3. Infrastructure Layer

Provides technical capabilities and interface implementations:

- **Repositories**: Database implementations (`app/infrastructure/persistence/repositories/`)
- **External Services**: Third-party integrations (`app/infrastructure/external/`)
- **Security**: Authentication and authorization (`app/infrastructure/security/`)
- **Messaging**: Message queue integrations (`app/infrastructure/messaging/`)
- **Caching**: Cache implementations (`app/infrastructure/cache/`)
- **ML Services**: Machine learning implementations (`app/infrastructure/ml/`)

### 4. Presentation Layer

Handles HTTP requests and responses:

- **API Endpoints**: REST API controllers (`app/presentation/api/v1/endpoints/` and `app/presentation/api/v1/routes/`)
- **Schemas**: Request/response models (`app/presentation/schemas/`)
- **Middleware**: Request/response processing (`app/presentation/middleware/`)
- **Dependencies**: Dependency injection (`app/presentation/api/dependencies/`)

## Key Design Patterns

The codebase utilizes several design patterns to ensure maintainability and extensibility:

### Repository Pattern

Abstracts data access:

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

### Dependency Injection

Uses FastAPI's dependency injection system:

```python
def get_user_repository(
    session: AsyncSession = Depends(get_db_session)
) -> IUserRepository:
    return SQLAlchemyUserRepository(session)
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

## SOLID Principles Application

The architecture follows SOLID principles:

1. **Single Responsibility**: Each class has one reason to change
2. **Open/Closed**: Entities are open for extension, closed for modification
3. **Liskov Substitution**: Interfaces can be substituted with implementations
4. **Interface Segregation**: Specific interfaces over general-purpose ones
5. **Dependency Inversion**: High-level modules depend on abstractions