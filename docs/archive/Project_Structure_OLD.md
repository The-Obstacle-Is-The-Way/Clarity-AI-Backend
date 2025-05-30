# Project Structure

## Directory Organization

```
app/
├── core/                  # Cross-cutting concerns and interfaces
│   ├── config/            # Application configuration
│   ├── domain/            # Core domain entities
│   │   └── entities/      # Shared domain entities
│   ├── exceptions/        # Base exceptions
│   ├── interfaces/        # Core interfaces
│   │   ├── repositories/  # Repository interfaces
│   │   ├── security/      # Security interfaces
│   │   └── services/      # Service interfaces
│   ├── services/          # Core application services
│   └── utils/             # Core utilities
│
├── domain/                # Business domain layer
│   ├── entities/          # Business entities
│   ├── enums/             # Domain enumerations
│   ├── exceptions/        # Domain-specific exceptions
│   ├── interfaces/        # Domain interfaces (legacy - being moved to core)
│   ├── services/          # Domain services
│   └── value_objects/     # Immutable value objects
│
├── application/           # Application services and use cases
│   ├── dtos/              # Data transfer objects
│   ├── exceptions/        # Application-specific exceptions
│   ├── interfaces/        # Application interfaces
│   ├── security/          # Security services
│   ├── services/          # Application services
│   └── use_cases/         # Business use cases
│
├── infrastructure/        # External interfaces implementation
│   ├── aws/               # AWS integrations
│   ├── cache/             # Caching implementations
│   ├── logging/           # Logging implementation
│   ├── messaging/         # Message queue implementations
│   ├── ml/                # Machine learning implementations
│   │   ├── biometric_correlation/ # Biometric analysis
│   │   ├── pat/           # PAT ML models
│   │   ├── pharmacogenomics/ # Drug interaction models
│   │   └── symptom_forecasting/ # Symptom prediction
│   ├── persistence/       # Database implementation
│   │   ├── models/        # ORM models
│   │   ├── repositories/  # Repository implementations
│   │   └── sqlalchemy/    # SQLAlchemy specific implementations
│   ├── rate_limiting/     # Rate limiting implementations
│   ├── repositories/      # Infrastructure repository implementations
│   ├── security/          # Security implementations
│   │   ├── audit/         # Audit logging
│   │   ├── auth/          # Authentication services
│   │   ├── jwt/           # JWT handling
│   │   └── phi/           # PHI protection
│   └── services/          # Infrastructure services
│
├── presentation/          # User interface layer
│   ├── api/               # API implementation
│   │   ├── dependencies/  # API dependencies
│   │   ├── schemas/       # Request/response schemas
│   │   └── v1/            # API version 1
│   │       ├── endpoints/ # API endpoint implementations
│   │       └── routes/    # API route definitions
│   └── middleware/        # HTTP middleware
│
└── tests/                 # Comprehensive test suite
    ├── api/               # API-specific tests
    ├── core/              # Core layer tests
    ├── domain/            # Domain layer tests
    ├── e2e/               # End-to-end tests
    ├── enhanced/          # Enhanced test utilities
    ├── fixtures/          # Test fixtures
    ├── helpers/           # Test helper utilities
    ├── infrastructure/    # Infrastructure tests
    ├── integration/       # Integration tests
    ├── mocks/             # Mock implementations
    ├── security/          # Security-focused tests
    ├── standalone/        # Standalone test utilities
    ├── unit/              # Unit tests
    └── utils/             # Test utilities
```

## Key Components

### Core Interfaces

Located in `app/core/interfaces/`, these define the contracts between architectural layers:

```python
# app/core/interfaces/repositories/user_repository_interface.py
class IUserRepository(Protocol):
    """Interface for user repository operations."""
    
    async def get_by_id(self, id: UUID) -> Optional[User]:
        """Get user by ID."""
        ...
    
    async def create(self, user: User) -> User:
        """Create a new user."""
        ...
```

### Domain Entities

Located in `app/domain/entities/`, these represent the core business objects:

```python
# app/domain/entities/patient.py
class Patient:
    """Patient entity representing a clinical patient."""
    
    def __init__(
        self,
        id: UUID,
        name: str,
        date_of_birth: date,
        status: PatientStatus,
        provider_id: UUID
    ):
        self.id = id
        self.name = name
        self.date_of_birth = date_of_birth
        self.status = status
        self.provider_id = provider_id
```

### Application Services

Located in `app/application/services/`, these orchestrate domain operations:

```python
# app/application/services/patient_service.py
class PatientService:
    """Service for patient-related operations."""
    
    def __init__(self, repository: IPatientRepository):
        self.repository = repository
    
    async def get_patient(self, id: UUID) -> Optional[Patient]:
        """Get a patient by ID."""
        return await self.repository.get_by_id(id)
```

### API Endpoints

Located in `app/presentation/api/v1/endpoints/`, these handle HTTP requests:

```python
# app/presentation/api/v1/endpoints/patients.py
@router.get("/{patient_id}", response_model=PatientResponse)
async def get_patient(
    patient_id: UUID,
    current_user: User = Depends(get_current_user),
    patient_service: PatientService = Depends(get_patient_service)
) -> PatientResponse:
    """Get a patient by ID."""
    patient = await patient_service.get_patient(patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    return PatientResponse.from_entity(patient)
```

## Test Organization

Tests are organized to mirror the application structure:

```
tests/
├── unit/                            # Unit tests
│   ├── domain/                      # Domain layer tests
│   ├── application/                 # Application layer tests
│   └── presentation/                # Presentation layer tests
│       └── api/
│           └── v1/
│               └── endpoints/       # API endpoint tests
└── integration/                     # Integration tests
    ├── infrastructure/              # Infrastructure integration
    └── api/                         # API integration tests
```

### Test Configuration

Test configuration is managed through fixtures in `conftest.py`:

```python
# app/tests/conftest.py
@pytest.fixture
async def db_session():
    """Create a test database session."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        future=True
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)