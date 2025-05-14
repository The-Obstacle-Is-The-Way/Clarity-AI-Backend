# Dependency Injection Guide

## Overview

The Clarity AI Backend implements a dependency injection (DI) system that leverages FastAPI's capabilities to create a decoupled architecture for the psychiatric digital twin platform. This document details the current DI implementation patterns, their strengths and limitations, and provides guidance for consistent usage.

## Current Implementation Patterns

The codebase currently uses several dependency injection patterns:

### 1. FastAPI Dependency System

The primary dependency injection mechanism is FastAPI's built-in dependency system:

```python
from fastapi import Depends, APIRouter
from app.presentation.api.dependencies.auth import get_current_user
from app.core.domain.entities.user import User

router = APIRouter()

@router.get("/patients")
async def get_patients(
    current_user: User = Depends(get_current_user),
    patient_service: PatientService = Depends(get_patient_service)
):
    """Get patients endpoint with injected dependencies."""
    return await patient_service.get_patients_for_user(current_user.id)
```

This pattern provides:
- Runtime resolution of dependencies
- Automatic dependency caching
- Support for dependency overrides in testing
- Clear dependency declaration at usage sites

### 2. Service Provider Functions

Service dependencies are typically provided through provider functions:

```python
# app/presentation/api/dependencies/services.py
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.presentation.api.dependencies.database import get_db
from app.core.interfaces.services import ActigraphyServiceInterface
from app.application.services import ActigraphyService

def get_actigraphy_service(
    db: AsyncSession = Depends(get_db)
) -> ActigraphyServiceInterface:
    """Provide an instance of the actigraphy service."""
    return ActigraphyService(db)
```

These provider functions:
- Create and configure service instances
- Handle dependency chaining
- Return interface types for loose coupling
- Can be overridden in tests

### 3. Constructor-Based Injection

Services and repositories use constructor-based injection to receive dependencies:

```python
# app/application/services/patient_service.py
class PatientService:
    """Service for patient-related operations."""
    
    def __init__(
        self,
        patient_repository: IPatientRepository,
        audit_logger: IAuditLogger
    ):
        """Initialize with required dependencies."""
        self.patient_repository = patient_repository
        self.audit_logger = audit_logger
        
    async def get_patient(self, patient_id: str, requesting_user_id: str) -> Patient:
        """Get patient by ID with proper audit logging."""
        # Implementation using injected dependencies
```

This approach:
- Makes dependencies explicit through constructor parameters
- Facilitates unit testing through dependency mocking
- Enables composition over inheritance
- Adheres to the Dependency Inversion Principle

### 4. Inline Mock Implementations

Some routes contain inline mock implementations for testing and development:

```python
# app/presentation/api/v1/routes/actigraphy.py
class MockPATService(IPATService):
    """Mock implementation for development/testing."""
    
    async def analyze_actigraphy(self, data: dict[str, Any]) -> dict[str, Any]:
        """Mock implementation."""
        return {"analysis_id": str(uuid.uuid4()), "result": "Mock result"}

async def get_pat_service() -> IPATService:
    """Provider for PAT service."""
    # This would typically use a factory or repository pattern in production
    return MockPATService()
```

This pattern:
- Enables rapid development and testing
- Violates separation of concerns (mixing test code with production)
- Creates maintainability challenges
- Should be replaced with proper test doubles in dedicated test modules

## Interface Patterns

The codebase uses multiple interface patterns:

### 1. Runtime-Checkable Protocols

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class ActigraphyServiceInterface(Protocol):
    """Interface for actigraphy services."""
    
    async def analyze_actigraphy(self, patient_id: str, readings: list) -> dict:
        """Analyze actigraphy data."""
        ...
```

### 2. Abstract Base Classes

```python
from abc import ABC, abstractmethod

class AuthServiceInterface(ABC):
    """Interface for authentication services."""
    
    @abstractmethod
    async def authenticate_user(self, username: str, password: str) -> User:
        """Authenticate a user."""
        pass
```

### 3. Simple Interface Classes

```python
class IPATService:
    """Interface for PAT service."""
    
    async def analyze(self, data: dict) -> dict:
        """Analyze data."""
        pass
```

## Best Practices for Dependency Injection

To maintain clean architecture and consistency, follow these best practices:

### 1. Use Interface Abstractions

Always depend on interfaces, not concrete implementations:

```python
# Good: Depends on abstraction
def get_patient_service(
    repo: IPatientRepository = Depends(get_patient_repository)
) -> IPatientService:
    return PatientService(repo)

# Avoid: Direct instantiation of concrete types
def get_patient_service_direct(
    db: AsyncSession = Depends(get_db)
) -> PatientService:
    return PatientService(SQLAlchemyPatientRepository(db))
```

### 2. Standardize Interface Locations

Place interfaces in the appropriate architectural layer:

- Domain repository interfaces: `app/domain/interfaces/repositories/`
- Application service interfaces: `app/core/interfaces/services/`
- Infrastructure interfaces: `app/core/interfaces/infrastructure/`

### 3. Use Constructor Injection

Prefer constructor injection for service dependencies:

```python
# Good: Constructor injection
class DigitalTwinService:
    def __init__(
        self,
        patient_repository: IPatientRepository,
        biometric_repository: IBiometricRepository,
        audit_logger: IAuditLogger
    ):
        self.patient_repository = patient_repository
        self.biometric_repository = biometric_repository
        self.audit_logger = audit_logger
```

### 4. Separate Test Implementations

Move mock implementations to dedicated test modules:

```python
# app/tests/mocks/services/mock_pat_service.py
class MockPATService(IPATService):
    """Mock PAT service for testing."""
    
    async def analyze_actigraphy(self, data: dict) -> dict:
        """Return mock analysis results."""
        return {"result": "Mock result"}
```

### 5. Use Factories for Complex Services

Implement factories for services with complex initialization:

```python
# app/infrastructure/factories/ml_service_factory.py
class MLServiceFactory:
    """Factory for creating ML service instances."""
    
    @staticmethod
    def create_pat_service(config: dict) -> IPATService:
        """Create a PAT service instance."""
        service_type = config.get("pat_service_type", "aws")
        
        if service_type == "aws":
            return AWSPATService(config)
        elif service_type == "local":
            return LocalPATService(config)
        else:
            raise ValueError(f"Unknown PAT service type: {service_type}")
```

## Dependency Resolution Flow

The dependency resolution flow in the application follows this pattern:

1. **HTTP Request** → FastAPI router
2. **Endpoint Handler** → Declares dependencies via `Depends()`
3. **Dependency Providers** → Create or retrieve dependencies
4. **Constructor Injection** → Dependencies injected into service constructors
5. **Interface Abstraction** → Services depend on interfaces
6. **Concrete Implementations** → Infrastructure layer provides concrete implementations

## Testing with Dependency Injection

The DI system enables effective testing through dependency overrides:

```python
# app/tests/api/test_patient_routes.py
from fastapi.testclient import TestClient
from unittest.mock import Mock
from app.main import app
from app.presentation.api.dependencies.services import get_patient_service

# Create mock service
mock_patient_service = Mock()
mock_patient_service.get_patients.return_value = [{"id": "1", "name": "Test Patient"}]

# Override dependency
app.dependency_overrides[get_patient_service] = lambda: mock_patient_service

# Test client
client = TestClient(app)

def test_get_patients():
    """Test get patients endpoint."""
    response = client.get("/api/v1/patients")
    assert response.status_code == 200
    assert len(response.json()) == 1
```

## Implementation Variations and Refinement

The current codebase exhibits several inconsistencies in the DI approach:

### Current Inconsistencies

1. **Mixed Interface Definitions**:
   - Some interfaces use Protocol, others use ABC
   - Interface locations vary across the codebase
   - Some interfaces are defined inline in routes

2. **Direct vs. Provider Instantiation**:
   - Some dependencies use provider functions
   - Others use direct instantiation
   - Some mix both approaches

3. **Mock Implementations in Production Code**:
   - Some mock services exist in route files
   - Others are properly isolated in test modules

### Refinement Strategy

To improve consistency, follow this refinement strategy:

1. **Interface Consolidation**:
   - Standardize on Protocol-based interfaces for runtime checking
   - Move interfaces to the appropriate architectural layer
   - Use consistent naming conventions (IServiceName)

2. **Provider Standardization**:
   - Create consistent provider functions for all dependencies
   - Implement proper factories for complex service creation
   - Remove direct instantiation in favor of dependency injection

3. **Test Isolation**:
   - Move all mock implementations to dedicated test modules
   - Use dependency overrides for testing
   - Implement proper test doubles (mocks, stubs, fakes)

## Conclusion

The dependency injection system in the Clarity AI Backend provides a foundation for clean architecture by decoupling components through interfaces and dependency providers. By addressing the current implementation variations and following the best practices outlined in this guide, the codebase can achieve a more consistent and maintainable dependency injection approach while preserving the flexibility needed for effective testing and HIPAA-compliant implementation.
