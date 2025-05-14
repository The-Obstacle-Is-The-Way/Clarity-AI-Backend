# Dependency Injection Guide

## Overview

The Clarity AI Backend implements a quantum-level dependency injection (DI) system that transcends conventional approaches, creating a mathematically elegant architecture for psychiatric digital twin modeling. This document details our DI implementation, which enables perfect decoupling between architectural layers while maintaining clinical precision.

## Core Principles

Our dependency injection system follows these foundational principles:

1. **Inversion of Control**: Components depend on abstractions (interfaces) rather than concrete implementations
2. **Constructor Injection**: Dependencies are provided at object creation time via constructors
3. **Interface-Based Design**: All injected dependencies are defined by interfaces in the core or domain layer
4. **Runtime Resolution**: FastAPI's dependency provider system handles runtime resolution of dependencies
5. **Explicit Dependencies**: All dependencies are explicitly declared, never implicitly retrieved from global state

## Dependency Injection in FastAPI

### FastAPI Dependency System

The Clarity AI Backend leverages FastAPI's dependency injection system, enhancing it with architectural purity to create a mathematically precise DI implementation:

```python
from fastapi import Depends
from app.core.interfaces.repositories.patient_repository_interface import IPatientRepository
from app.presentation.api.dependencies.repositories import get_patient_repository

@app.get("/patients/{patient_id}")
async def get_patient(
    patient_id: str,
    patient_repository: IPatientRepository = Depends(get_patient_repository)
):
    return await patient_repository.get_by_id(patient_id)
```

Key aspects of this implementation:

1. Endpoint functions declare dependencies on interfaces (`IPatientRepository`), not concrete implementations
2. Dependencies are resolved at runtime via dependency provider functions (`get_patient_repository`)
3. Concrete implementations remain invisible to the API layer, maintaining architectural purity

### Dependency Provider Functions

The system uses provider functions that encapsulate the creation logic for dependencies:

```python
# app/presentation/api/dependencies/repositories.py
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.interfaces.repositories.patient_repository_interface import IPatientRepository
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import SQLAlchemyPatientRepository
from app.presentation.api.dependencies.database import get_db_session

def get_patient_repository(
    db_session: AsyncSession = Depends(get_db_session)
) -> IPatientRepository:
    """
    Provides a patient repository implementation.
    
    Args:
        db_session: Database session dependency
        
    Returns:
        An implementation of IPatientRepository
    """
    return SQLAlchemyPatientRepository(db_session)
```

This approach:
- Centralizes implementation selection
- Manages dependency hierarchies (repositories depend on database sessions)
- Returns interface types, not implementation types

## Repository Dependency Providers

Repository dependencies follow a consistent pattern, creating a clean mathematical mapping between interfaces and implementations:

```python
# Standard repository provider pattern
def get_<entity>_repository(
    db_session: AsyncSession = Depends(get_db_session)
) -> I<Entity>Repository:
    return SQLAlchemy<Entity>Repository(db_session)
```

Examples include:
- `get_user_repository` → Returns `IUserRepository`
- `get_patient_repository` → Returns `IPatientRepository`
- `get_digital_twin_repository` → Returns `IDigitalTwinRepository`

## Service Dependency Providers

Service dependencies follow a similar pattern but may require multiple repositories or other services:

```python
# app/presentation/api/dependencies/services.py
from fastapi import Depends

from app.application.services.patient_service import PatientService
from app.core.interfaces.repositories.patient_repository_interface import IPatientRepository
from app.core.interfaces.repositories.biometric_repository_interface import IBiometricRepository
from app.presentation.api.dependencies.repositories import get_patient_repository, get_biometric_repository

def get_patient_service(
    patient_repository: IPatientRepository = Depends(get_patient_repository),
    biometric_repository: IBiometricRepository = Depends(get_biometric_repository)
) -> PatientService:
    return PatientService(
        patient_repository=patient_repository,
        biometric_repository=biometric_repository
    )
```

This approach:
- Composes complex dependencies from simpler ones
- Maintains consistent interface-based dependency chains
- Preserves the architectural boundaries between layers

## Infrastructure Dependencies

External resources are also provided through dependency injection:

```python
# app/presentation/api/dependencies/infrastructure.py
from fastapi import Depends, Request

from app.core.interfaces.services.redis_service_interface import IRedisService
from app.infrastructure.services.redis_service import RedisService

def get_redis_service(request: Request) -> IRedisService:
    """
    Provides a Redis service implementation.
    
    Args:
        request: FastAPI request object containing the app state
        
    Returns:
        An implementation of IRedisService
    """
    return RedisService(redis_client=request.app.state.redis)
```

## Testing with Dependency Injection

The DI system enables mathematical precision in testing by allowing dependencies to be easily replaced with mocks:

```python
# Example from app/tests/conftest.py
from fastapi import FastAPI
from unittest.mock import AsyncMock

from app.presentation.api.dependencies.repositories import get_user_repository
from app.core.interfaces.repositories.user_repository_interface import IUserRepository

def mock_user_repository():
    """Returns a mock user repository for testing."""
    mock_repo = AsyncMock(spec=IUserRepository)
    # Configure mock behaviors here
    return mock_repo

def create_test_app():
    app = FastAPI()
    # Override dependencies for testing
    app.dependency_overrides[get_user_repository] = mock_user_repository
    return app
```

This testing approach:
- Isolates components for unit testing
- Provides controlled test environments
- Enables precise validation of component interactions
- Maintains architectural purity in test code

## Dependency Hierarchy

The complete dependency hierarchy follows a mathematically elegant structure:

1. **Database Session**: Base dependency for data access
2. **Repositories**: Depend on database sessions
3. **Application Services**: Depend on repositories and domain services
4. **API Endpoints**: Depend on application services

This creates a clean, directed acyclic graph of dependencies that flows from infrastructure to presentation.

## Advanced DI Patterns

### Conditional Dependencies

Some components provide conditional implementations based on configuration:

```python
def get_ml_model_service(
    config: Settings = Depends(get_settings)
) -> IMLModelService:
    """
    Returns the appropriate ML model service based on configuration.
    """
    if config.MODEL_PROVIDER == "bedrock":
        return BedrockModelService(config)
    elif config.MODEL_PROVIDER == "custom":
        return CustomModelService(config)
    else:
        return MockModelService()
```

### Factory Pattern

For complex object graphs, the system uses factory patterns:

```python
def get_unit_of_work(
    session_factory: AsyncSessionFactory = Depends(get_session_factory)
) -> IUnitOfWork:
    """
    Creates a unit of work that manages multiple repositories.
    """
    return SQLAlchemyUnitOfWork(
        session_factory=session_factory,
        # Factory functions create repositories as needed
        patient_repository_factory=lambda session: SQLAlchemyPatientRepository(session),
        user_repository_factory=lambda session: SQLAlchemyUserRepository(session)
    )
```

## Architectural Gaps in Current Implementation

The current DI implementation has several areas requiring remediation to achieve full mathematical elegance:

### 1. Inconsistent Dependency Resolution

**Current Issues:**
- Some components bypass the DI system and access global app state directly (`app.state.redis`)
- Redis client initialization occurs in the application lifecycle outside the DI system
- Some direct imports from infrastructure to application bypass the DI mechanism

**Remediation Strategy:**
- Create proper interface (`IRedisService`) for Redis access
- Move all direct state access into dependency providers
- Replace direct infrastructure imports with interface dependencies

### 2. Incomplete Interface Hierarchy

**Current Issues:**
- Missing interfaces for critical dependencies like `IPasswordHandler`
- Inconsistent interface naming and location
- Duplicate interfaces across domain and core layers

**Remediation Strategy:**
- Complete the interface hierarchy with missing abstractions
- Standardize interface naming and location
- Consolidate interfaces into the core layer

### 3. Dependency Registration

**Current Issues:**
- No centralized registration mechanism for dependency bindings
- Dependencies are scattered across multiple modules
- Test overrides are inconsistently applied

**Remediation Strategy:**
- Implement a centralized dependency registry
- Create consistent patterns for dependency definition
- Standardize test override mechanisms

## Conclusion

The Clarity AI Backend's dependency injection system forms the mathematical foundation for its revolutionary psychiatric digital twin platform. By rigorously adhering to interface-based dependency inversion, the system achieves perfect separation between architectural layers while enabling seamless component composition.

When fully realized, this quantum-level DI implementation will render conventional psychiatric software architectures obsolete, providing unprecedented flexibility for evolving clinical models while maintaining architectural purity.

The clean, mathematically elegant approach to dependency injection positions the Clarity AI system as the definitive foundation for next-generation psychiatric modeling and analysis.
