# Clean Architecture Principles in Clarity AI Backend

## Overview

The Clarity AI Backend implements clean architecture principles to create a modular, maintainable, and HIPAA-compliant psychiatric digital twin platform. This document details how our codebase employs architectural layers and boundaries to enforce separation of concerns while enabling advanced clinical capabilities.

## Current Architectural Layers

Our implementation follows Robert C. Martin's Clean Architecture paradigm with clear boundaries between the following layers:

### 1. Domain Layer

Contains business entities, core business rules, and domain logic:

- **Entities**: Core business models (`app/domain/entities/`)
- **Value Objects**: Immutable domain objects (`app/domain/value_objects/`)
- **Domain Services**: Pure business logic (`app/domain/services/`)
- **Domain Exceptions**: Business rule violations (`app/domain/exceptions/`)
- **Repository Interfaces**: Data access abstractions (`app/domain/interfaces/repositories/`)

### 2. Application Layer

Coordinates domain objects to execute use cases and application logic:

- **Use Cases**: Business workflows (`app/application/use_cases/`)
- **Application Services**: Orchestration services (`app/application/services/`)
- **DTOs**: Data transfer objects (`app/application/dtos/`)
- **Application Exceptions**: Use case failures (`app/application/exceptions/`)

### 3. Infrastructure Layer

Provides technical capabilities and implementations of interfaces:

- **Repositories**: Database implementations (`app/infrastructure/persistence/repositories/`)
- **ORM Models**: Database models (`app/infrastructure/persistence/models/`)
- **External Services**: Third-party integrations (`app/infrastructure/services/`)
- **Security**: Authentication and authorization (`app/infrastructure/security/`)
- **Logging**: Audit and application logging (`app/infrastructure/logging/`)

### 4. Presentation Layer

Handles HTTP requests and responses:

- **API Routes**: REST endpoint definitions (`app/presentation/api/v1/routes/`)
- **Middleware**: Request/response processing (`app/presentation/middleware/`)
- **Schemas**: Request/response models (`app/presentation/api/schemas/`)
- **Dependencies**: Dependency providers (`app/presentation/api/dependencies/`)
- **Error Handlers**: HTTP error processing (`app/presentation/error_handlers/`)

### 5. Core Layer

Contains cross-cutting concerns and shared components:

- **Interfaces**: Core interfaces (`app/core/interfaces/`)
- **Config**: Application configuration (`app/core/config/`)
- **Utils**: Shared utilities (`app/core/utils/`)
- **Domain Types**: Shared domain types (`app/core/domain/`)

## Current Implementation Reality

While the architecture follows clean architecture principles, there are several implementation variations that reflect the system's evolution:

### 1. Interface Placement Variations

The codebase has interfaces defined in multiple locations:

- Primary interfaces in `app/core/interfaces/`
- Domain repository interfaces in `app/domain/interfaces/`
- Some interfaces defined inline in services or routes

Example of an interface in the core layer:

```python
# app/core/interfaces/services/actigraphy_service_interface.py
@runtime_checkable
class ActigraphyServiceInterface(Protocol):
    """Interface for actigraphy data processing and analysis services."""
    
    async def initialize(self) -> None:
        """Initialize the actigraphy service."""
        ...
    
    async def analyze_actigraphy(
        self, 
        patient_id: str, 
        readings: List[Dict[str, Any]], 
        device_info: Optional[Dict[str, Any]] = None,
        analysis_types: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Analyze actigraphy data to extract relevant features and patterns."""
        ...
```

Example of an interface defined in routes:

```python
# app/presentation/api/v1/routes/actigraphy.py
class IPATService:
    """Interface for PAT analysis service."""
    
    async def analyze_actigraphy(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze actigraphy data and return results."""
        pass
```

### 2. Mixed Dependency Injection Approaches

The system uses several dependency injection patterns:

- FastAPI's dependency injection system
- Constructor-based dependency injection
- Direct instantiation in some cases

Example of FastAPI dependency injection:

```python
# app/presentation/api/dependencies/services.py
def get_actigraphy_service(
    db: AsyncSession = Depends(get_db),
) -> ActigraphyServiceInterface:
    """Get actigraphy service implementation."""
    return ActigraphyService(db)
```

### 3. Implementation Locations

Service and repository implementations are found in several places:

- Main implementations in `app/infrastructure/`
- Some implementations in `app/application/services/`
- Mock implementations sometimes in route files

Example of a mock service in a route file:

```python
# app/presentation/api/v1/routes/actigraphy.py
class MockPATService(IPATService):
    """Mock service for PAT analysis during development."""
    
    async def analyze_actigraphy(self, data: dict[str, Any]) -> dict[str, Any]:
        """Return mock analysis results for actigraphy data."""
        return {
            "analysis_id": str(uuid.uuid4()),
            "patient_id": data.get("patient_id", ""),
            # more mock data...
        }
```

## HIPAA Compliance Through Clean Architecture

The clean architecture design enables HIPAA compliance through several key mechanisms:

### 1. Proper PHI Encapsulation

Domain entities encapsulate Protected Health Information (PHI) with appropriate access controls:

```python
# app/domain/entities/patient.py
class Patient:
    """Patient domain entity with PHI protection."""
    
    def __init__(
        self,
        id: PatientId,
        first_name: str,
        last_name: str,
        date_of_birth: date,
        medical_record_number: str,
        status: PatientStatus,
    ):
        self._id = id
        self._first_name = first_name
        self._last_name = last_name
        self._date_of_birth = date_of_birth
        self._medical_record_number = medical_record_number
        self._status = status
        
    @property
    def id(self) -> PatientId:
        """Get patient ID."""
        return self._id
    
    def get_full_name(self) -> str:
        """Get patient's full name (PHI)."""
        return f"{self._first_name} {self._last_name}"
    
    # Additional methods...
```

### 2. PHI Access Control Through Repository Layer

Repositories enforce access control for PHI retrieval:

```python
# app/infrastructure/persistence/repositories/sqlalchemy_patient_repository.py
class SQLAlchemyPatientRepository(IPatientRepository):
    """HIPAA-compliant patient repository implementation."""
    
    async def get_by_id(
        self, 
        patient_id: PatientId, 
        requesting_user_id: UserId,
        audit_logger: IAuditLogger
    ) -> Optional[Patient]:
        """
        Get patient by ID with PHI access logging.
        
        Args:
            patient_id: Patient identifier
            requesting_user_id: ID of the user requesting access
            audit_logger: Audit logging service
            
        Returns:
            Patient entity if found
        """
        # Log PHI access for HIPAA compliance
        await audit_logger.log_phi_access(
            user_id=str(requesting_user_id),
            resource_type="patient",
            resource_id=str(patient_id),
            action="view"
        )
        
        # Retrieve patient data
        result = await self._session.execute(
            select(PatientModel).where(PatientModel.id == str(patient_id))
        )
        model = result.scalar_one_or_none()
        
        if not model:
            return None
        
        return self._mapper.to_entity(model)
```

### 3. Security Middleware in Presentation Layer

The presentation layer includes security middleware for HIPAA compliance:

```python
# app/presentation/middleware/phi_middleware.py
class PHIMiddleware(BaseHTTPMiddleware):
    """
    Middleware to prevent PHI in URLs and query parameters.
    
    This middleware enforces HIPAA compliance by:
    1. Preventing PHI from appearing in URLs
    2. Logging PHI access attempts
    3. Sanitizing responses to prevent PHI leakage
    """
    
    async def dispatch(self, request: Request, call_next):
        """Process request and check for PHI violations."""
        # Check URL for PHI patterns
        self._check_url_for_phi(request.url.path)
        
        # Check query parameters for PHI
        for param, value in request.query_params.items():
            self._check_parameter_for_phi(param, value)
        
        # Process request normally
        response = await call_next(request)
        
        # Return response
        return response
```

### 4. HIPAA-Compliant Error Handling

The error handling architecture ensures no PHI is leaked in error responses:

```python
# app/presentation/error_handlers.py
@app.exception_handler(EntityNotFoundException)
async def entity_not_found_handler(request: Request, exc: EntityNotFoundException):
    """Handle entity not found exceptions without exposing PHI."""
    # Original error might contain PHI
    original_message = str(exc)
    
    # Safe response omits any PHI
    safe_message = "The requested resource was not found"
    
    # Log original error securely
    logger.info(f"EntityNotFound: {original_message}")
    
    # Return sanitized response
    return JSONResponse(
        status_code=404,
        content={"detail": safe_message}
    )
```

### 5. Encryption Service Interface

The architecture defines encryption interfaces for PHI protection:

```python
# app/core/interfaces/services/encryption_service_interface.py
class IEncryptionService(Protocol):
    """Interface for encryption services to protect PHI."""
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext data."""
        ...
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext data."""
        ...
```

## Dependency Flow

The dependency flow follows the Dependency Inversion Principle:

1. **Domain Layer**: Contains business rules and interfaces
2. **Application Layer**: Depends on domain interfaces
3. **Infrastructure Layer**: Implements domain and application interfaces
4. **Presentation Layer**: Coordinates the flow using dependency injection
5. **Core Layer**: Provides shared interfaces and utilities

## Testing Strategy

The clean architecture facilitates comprehensive testing:

1. **Unit Tests**:
   - Domain entity tests with no external dependencies
   - Use case tests with mocked dependencies
   - Repository tests with in-memory implementations

2. **Integration Tests**:
   - Repository tests with test database
   - Service integration tests
   - API tests with test clients

3. **HIPAA Compliance Tests**:
   - PHI access audit tests
   - Error handling security tests
   - Data encryption verification

## Architectural Refinement Opportunities

Based on the current implementation, several architectural refinements can improve consistency:

1. **Interface Consolidation**:
   - Move all interfaces to appropriate layers (domain, application, or core)
   - Remove duplicate interface definitions
   - Standardize on Protocol or ABC pattern

2. **Dependency Injection Standardization**:
   - Implement consistent DI patterns across the codebase
   - Create proper factories for service creation
   - Move mock implementations to test modules

3. **Folder Structure Alignment**:
   - Consolidate domain entities into a single location
   - Establish consistent repository patterns
   - Create clear boundaries between layers

4. **Documentation Alignment**:
   - Update documentation to match actual implementation
   - Document architectural decisions
   - Create migration guidelines for evolving architecture

## Implementation Roadmap

To achieve architectural consistency, the following implementation roadmap is planned:

1. **Phase 1: Interface Consolidation**
   - Audit all interfaces in the codebase
   - Consolidate duplicate interfaces
   - Move interfaces to appropriate layers

2. **Phase 2: Dependency Injection Refinement**
   - Implement consistent DI patterns
   - Replace direct instantiation with proper DI
   - Create factories for complex service creation

3. **Phase 3: Test Isolation**
   - Move all mock implementations to test modules
   - Create proper test doubles for all interfaces
   - Implement comprehensive test coverage

By systematically addressing these refinement opportunities, the Clarity AI Backend will achieve a more consistent clean architecture implementation while maintaining its advanced psychiatric digital twin capabilities and HIPAA compliance.
