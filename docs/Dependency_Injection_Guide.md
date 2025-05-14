# Dependency Injection Guide

## Overview

The Clarity AI Backend implements a dependency injection (DI) system leveraging FastAPI's built-in capabilities to create a decoupled architecture for the psychiatric digital twin platform. This document details the DI implementation, which enables separation between architectural layers while maintaining consistent interfaces.

## Core Principles

Our dependency injection system follows these foundational principles:

1. **Inversion of Control**: Components depend on abstractions (interfaces) rather than concrete implementations
2. **FastAPI Dependency Injection**: Dependencies are provided using FastAPI's `Depends` function
3. **Interface-Based Design**: Dependencies are defined through interfaces, abstract base classes, or protocols
4. **Runtime Resolution**: FastAPI's dependency provider system handles runtime resolution of dependencies
5. **Explicit Dependencies**: Dependencies are explicitly declared in function signatures

## Dependency Injection in FastAPI

### FastAPI Dependency System

The Clarity AI Backend leverages FastAPI's dependency injection system:

```python
from fastapi import Depends, APIRouter
from app.presentation.api.dependencies.auth import require_roles
from app.core.domain.entities.user import UserRole

router = APIRouter()

@router.get("/protected-endpoint")
async def protected_endpoint(
    current_user = Depends(require_roles([UserRole.ADMIN]))
):
    return {"message": "You have access to this endpoint"}
```

Key aspects of this implementation:

1. Endpoints declare dependencies using the `Depends()` function
2. Dependencies can enforce authentication and authorization (e.g., `require_roles`)
3. Dependencies can be chained, with one dependency depending on another

### Dependency Provider Functions

The system uses provider functions that encapsulate the creation logic for dependencies:

```python
# Example from app/presentation/api/v1/routes/actigraphy.py
async def get_pat_service(db: AsyncSession = Depends(get_db)) -> IPATService:
    """Get the PAT service implementation."""
    # In a production environment, this would use a factory pattern
    return MockPATService()
```

This approach:
- Centralizes implementation selection
- Enables substitution of implementations
- Facilitates testing through dependency overrides

## Interface Patterns

The codebase uses several patterns for defining interfaces:

### 1. Abstract Base Classes (ABC)

```python
# Example from app/core/interfaces/services/ml/pat_interface.py
class PATInterface(ABC):
    """Interface for psychiatric assessment tool services."""
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the PAT service with required models and configurations."""
        pass
```

### 2. Protocol Classes

```python
# Example from app/core/interfaces/services/actigraphy_service_interface.py
@runtime_checkable
class ActigraphyServiceInterface(Protocol):
    """Interface for actigraphy data processing and analysis services."""
    
    async def initialize(self) -> None:
        """Initialize the actigraphy service."""
        ...
```

### 3. Simple Interface Classes

```python
# Example from app/presentation/api/v1/routes/actigraphy.py
class IPATService:
    """Interface for PAT analysis service."""
    
    async def analyze_actigraphy(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze actigraphy data and return results."""
        pass
```

## Database Session Dependencies

Database access is provided through dependencies:

```python
# app/presentation/api/dependencies/database.py
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

async def get_db() -> AsyncSession:
    """Provide a database session."""
    async with AsyncSessionLocal() as session:
        yield session
```

This approach:
- Ensures proper session lifecycle management
- Centralizes database access
- Enables transaction management

## Authentication and Authorization Dependencies

Security is implemented through dependency chains:

```python
# Example from app/presentation/api/dependencies/auth.py
from fastapi import Depends, HTTPException, status
from app.core.domain.entities.user import UserRole

def require_roles(allowed_roles: list[UserRole]):
    """Dependency that requires the user to have specific roles."""
    
    async def _require_roles(current_user = Depends(get_current_user)):
        if not any(role in current_user.roles for role in allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
        
    return _require_roles
```

This creates:
- Role-based access control
- Consistent security enforcement
- Clear security requirements in endpoint definitions

## Testing with Dependency Injection

The DI system facilitates testing by allowing dependencies to be easily replaced with mocks:

```python
# Testing pattern
from fastapi.testclient import TestClient
from app.presentation.api.dependencies.services import get_pat_service

# Create a mock service
mock_pat_service = MockPATService()

# Override the dependency
app.dependency_overrides[get_pat_service] = lambda: mock_pat_service

# Create test client
client = TestClient(app)

# Make test request
response = client.post("/actigraphy/analyze", json=test_data)
```

This testing approach:
- Isolates components for unit testing
- Provides controlled test environments
- Enables verification of component interactions

## Current Implementation Patterns

The Clarity AI Backend uses several dependency injection patterns:

### 1. Simple Service Dependencies

```python
# Direct dependency on a service
@router.post("/analyze")
async def analyze_data(
    data: AnalysisRequest,
    pat_service: IPATService = Depends(get_pat_service)
):
    return await pat_service.analyze(data)
```

### 2. Authentication Dependencies

```python
# Authentication and authorization dependency
@router.get("/patient/{patient_id}")
async def get_patient(
    patient_id: str,
    current_user = Depends(require_roles([UserRole.CLINICIAN, UserRole.ADMIN]))
):
    # Endpoint implementation
```

### 3. Nested Dependencies

```python
# Dependencies that depend on other dependencies
async def get_patient_service(
    db: AsyncSession = Depends(get_db),
    auth_service = Depends(get_auth_service)
) -> PatientService:
    return PatientService(db, auth_service)
```

### 4. Optional Query Parameters

```python
# Optional query parameters as dependencies
@router.get("/endpoint")
async def endpoint(
    service: Service = Depends(get_service),
    optional_param: Optional[str] = Query(default=None)
):
    # Implementation
```

## Current Implementation Variations

The current codebase exhibits several variations in the dependency injection approach:

### 1. Mixed Interface Definitions

- Some interfaces are defined using ABC
- Others use Protocol
- Some are simple classes with pass methods
- Interface locations vary (core/interfaces, inline in routes)

### 2. Mock Implementations in Routes

```python
# Example from actigraphy.py
class MockPATService(IPATService):
    """Temporary mock service for PAT analysis to make tests pass."""
    
    async def analyze_actigraphy(self, data: ActigraphyAnalysisRequest) -> dict[str, Any]:
        """Mock implementation of actigraphy analysis."""
        # Mock implementation
```

### 3. Inconsistent Dependency Resolution

- Some dependencies return interface types
- Others return concrete implementation types
- Some services are injected directly, others via factories

## Recommended Best Practices

For future development and refactoring, we recommend these dependency injection best practices:

1. **Consistent Interface Definitions**: Define all interfaces in the core/interfaces directory using a consistent pattern (Protocol or ABC)

2. **Centralized Dependency Providers**: Place all dependency provider functions in the appropriate modules under app/presentation/api/dependencies/

3. **Return Interface Types**: Ensure dependency providers return interface types, not concrete implementations

4. **Move Mock Implementations to Tests**: Relocate mock implementations from route files to appropriate test modules

5. **Factory Pattern for Complex Dependencies**: Use factory patterns for dependencies that require complex initialization

6. **Consistent Error Handling**: Implement consistent error handling in dependency providers

## Conclusion

The Clarity AI Backend's dependency injection system effectively leverages FastAPI's built-in capabilities to create a decoupled architecture. While there are some implementation variations that could be standardized, the current approach successfully enables component isolation, testing, and maintenance.
