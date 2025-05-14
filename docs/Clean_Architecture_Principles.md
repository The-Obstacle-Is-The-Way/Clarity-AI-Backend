# Clean Architecture Principles in Clarity AI Backend

## Overview

The Clarity AI Backend implements a clean architecture approach that separates concerns into distinct layers. This document details how our codebase employs architectural principles to create a psychiatric digital twin platform that maintains conceptual integrity while enabling advanced clinical capabilities.

## Current Architectural Layers

Our implementation follows Robert C. Martin's Clean Architecture paradigm with boundaries between the following layers:

### 1. Domain Layer

Contains business entities and core business logic:

- **Entities**: Core domain models (`app/domain/entities/` and `app/core/domain/entities/`)
- **Value Objects**: Immutable data structures (`app/domain/value_objects/`)
- **Domain Services**: Business logic services (`app/domain/services/`)
- **Repository Interfaces**: Data access abstractions (`app/core/interfaces/repositories/`)

### 2. Application Layer (`app/application/`)

Orchestrates domain objects to implement use cases:

- **Use Cases**: Clinical workflows implementing specific scenarios (`app/application/use_cases/`)
- **Application Services**: Coordinate domain services (`app/application/services/`)
- **DTOs**: Data Transfer Objects for crossing architectural boundaries (`app/application/dtos/`)

### 3. Infrastructure Layer (`app/infrastructure/`)

Provides concrete implementations of interfaces defined in inner layers:

- **Repositories**: Database access implementations (`app/infrastructure/persistence/repositories/`)
- **External Services**: Integrations with third-party systems (`app/infrastructure/services/`)
- **Security**: Concrete security implementations (`app/infrastructure/security/`)
- **Logging**: Audit and application logging (`app/infrastructure/logging/`)

### 4. Presentation Layer (`app/presentation/`)

Manages API endpoints and user interaction:

- **API Routes**: REST API definitions (`app/presentation/api/v1/routes/`)
- **API Endpoints**: Alternative endpoint structure (`app/presentation/api/v1/endpoints/`)
- **Middleware**: API request processing components (`app/presentation/middleware/`)
- **Schemas**: Input/output data validation models (`app/presentation/api/schemas/`)
- **Dependencies**: FastAPI dependency providers (`app/presentation/api/dependencies/`)

### 5. Core Layer (`app/core/`)

Contains cross-cutting concerns and shared components:

- **Interfaces**: Key abstractions implemented across layers (`app/core/interfaces/`)
- **Domain**: Core domain types shared across the system (`app/core/domain/`)
- **Config**: System configuration management (`app/core/config/`)
- **Services**: Core service interfaces and base implementations (`app/core/services/`)
- **Utils**: Utility functions used across the application (`app/core/utils/`)
- **Exceptions**: Common exception types (`app/core/exceptions/`)

## Dependency Inversion Implementation

The system implements dependency inversion through several mechanisms:

1. **Interface Definitions**: Service and repository interfaces defined in core layer

```python
# Example from app/core/interfaces/repositories/token_repository_interface.py
class TokenRepositoryInterface(Protocol):
    async def get_by_token(self, token: str) -> Optional[TokenModel]:
        ...
```

2. **Protocol-based Interfaces**: Using Python's Protocol class for runtime-checkable interfaces

```python
@runtime_checkable
class ActigraphyServiceInterface(Protocol):
    """Interface for actigraphy data processing and analysis services."""
    
    async def initialize(self) -> None:
        """Initialize the actigraphy service."""
        ...
```

3. **Dependency Injection**: Services depend on abstractions through FastAPI's dependency injection

```python
# Example from endpoint
async def get_pat_service(db: AsyncSession = Depends(get_db)) -> IPATService:
    """Get the PAT service implementation."""
    return MockPATService()
```

4. **Abstract Base Classes**: Using ABC for enforcing interface implementation

```python
class PATInterface(ABC):
    """Interface for psychiatric assessment tool services."""
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the PAT service with required models and configurations."""
        pass
```

## HIPAA Compliance Through Architecture

Clean architecture enables HIPAA compliance through:

1. **Access Control**: Role-based authentication via dependency injection
2. **Audit Logging**: Centralized audit logging for PHI access
3. **Data Validation**: Strict schema validation with Pydantic
4. **Error Handling**: Structured error responses that avoid PHI exposure
5. **Secure Communications**: TLS enforcement and proper header management

## Flow of Control

1. **HTTP Request** → FastAPI routes in presentation layer
2. **Request Validation** → Pydantic models in presentation schemas
3. **Dependency Resolution** → FastAPI dependency providers inject required services
4. **Application Service** → Orchestrates the use case from the application layer
5. **Domain Logic** → Business rules executed in the domain layer
6. **Data Access** → Repository interfaces called by application services
7. **Response Creation** → Domain objects mapped to response schemas
8. **HTTP Response** → Serialized data returned to client

## Testing Strategy

The clean architecture enables a comprehensive testing strategy:

1. **Unit Tests**: Testing individual components with mocked dependencies
2. **Integration Tests**: Testing interactions between components
3. **API Tests**: Testing HTTP endpoints with the full application stack
4. **Security Tests**: Validating authentication and authorization controls

## Current Architectural Implementation Status

While the Clarity AI Backend follows clean architecture principles, there are several implementation patterns that represent pragmatic adaptations:

### 1. Dual Location for Interfaces

**Current Implementation:**

- Some interfaces exist in both `app/core/interfaces/` and directly within service modules
- Interface implementations sometimes exist in multiple places
- Some interfaces use Protocol pattern while others use ABC

**Example:**
- `ActigraphyServiceInterface` in core interfaces
- `IPATService` defined inline in routes

### 2. Mixed Implementation Patterns

**Current Implementation:**

- Some services use constructor-based dependency injection
- Others use function-based dependency injection via FastAPI's Depends
- Mock implementations sometimes exist in route files rather than separate test modules

**Example:**
```python
# Inline mock in routes file
class MockPATService(IPATService):
    """Temporary mock service for PAT analysis to make tests pass."""
    
    async def analyze_actigraphy(self, data: ActigraphyAnalysisRequest) -> dict[str, Any]:
        # Mock implementation
```

### 3. Domain Entities in Multiple Locations

**Current Implementation:**

- Domain entities exist in both `app/domain/entities/` and `app/core/domain/entities/`
- Some domain logic exists directly in service implementations
- Some services directly implement interfaces rather than using composition

### 4. Endpoint Structure Variations

**Current Implementation:**

- Some endpoints are in `app/presentation/api/v1/routes/`
- Others are in `app/presentation/api/v1/endpoints/`
- Different patterns for organizing related endpoints

## Roadmap for Architectural Refinement

To achieve a more consistent clean architecture implementation, the following improvements are planned:

1. **Interface Consolidation**: Standardize interface location and implementation pattern
2. **Dependency Injection Framework**: Implement consistent DI patterns across the codebase
3. **Testing Isolation**: Move mock implementations to dedicated test modules
4. **Entity Organization**: Consolidate domain entities into a single location
5. **Endpoint Standardization**: Create consistent patterns for API endpoints
6. **Service Layer Consistency**: Standardize service implementation patterns

## Conclusion

The Clarity AI Backend implements clean architecture principles with some pragmatic adaptations. By addressing the implementation inconsistencies identified in this document, the system will continue to evolve toward a more consistent and maintainable architecture while delivering advanced psychiatric digital twin capabilities.
