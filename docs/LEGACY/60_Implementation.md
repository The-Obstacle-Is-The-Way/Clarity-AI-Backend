# Implementation Guide

This document provides practical guidance for implementing and extending the Novamind Digital Twin platform. It covers coding standards, best practices, and step-by-step instructions for common development tasks.

---

## 1. Development Environment Setup

### 1.1. Prerequisites

- Python 3.10+
- Git
- Docker and Docker Compose (recommended)
- IDE with Python support (VS Code, PyCharm, etc.)

### 1.2. Local Setup

Clone the repository and set up the development environment:

```bash
# Clone the repository
git clone git@github.com:novamind/digital-twin-platform.git
cd digital-twin-platform

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install
```

### 1.3. Environment Configuration

Create a `.env` file in the project root:

```
# API Configuration
API_ENV=development
API_DEBUG=true
API_PORT=8000

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=novamind

# Security
SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

### 1.4. Running the Application

```bash
# Run with uvicorn
uvicorn backend.app.main:app --reload

# Or run with Docker Compose
docker-compose up
```

## 2. Project Structure

The project follows a Clean Architecture structure:

```
/backend/
├── app/                     # Main application package
│   ├── api/                 # API Layer (FastAPI routers and endpoints)
│   │   ├── dependencies/    # FastAPI dependencies
│   │   ├── routes/          # API route definitions
│   │   └── middleware/      # API middleware
│   ├── application/         # Application Layer
│   │   ├── services/        # Application services
│   │   ├── use_cases/       # Use case implementations
│   │   ├── interfaces/      # Application interfaces
│   │   └── dtos/            # Data Transfer Objects
│   ├── domain/              # Domain Layer
│   │   ├── entities/        # Domain entities
│   │   ├── value_objects/   # Value objects
│   │   ├── services/        # Domain services
│   │   ├── repositories/    # Repository interfaces
│   │   └── events/          # Domain events
│   ├── infrastructure/      # Infrastructure Layer
│   │   ├── repositories/    # Repository implementations
│   │   ├── database/        # Database configuration
│   │   ├── security/        # Security implementations
│   │   ├── messaging/       # Message queue adapters
│   │   ├── storage/         # Storage adapters
│   │   └── services/        # External service adapters
│   ├── core/                # Core Layer (Shared utilities)
│   │   ├── config/          # Configuration
│   │   ├── logging/         # Logging utilities
│   │   ├── errors/          # Error handling
│   │   └── utils/           # Common utilities
│   └── main.py              # Application entry point
├── tests/                   # Test suite
├── alembic/                 # Database migrations
└── scripts/                 # Utility scripts
```

## 3. Coding Standards

### 3.1. Python Style Guide

The project follows:

- [PEP 8](https://www.python.org/dev/peps/pep-0008/) for general Python style
- [PEP 484](https://www.python.org/dev/peps/pep-0484/) for type hints
- [Black](https://black.readthedocs.io/) for code formatting
- [isort](https://pycqa.github.io/isort/) for import sorting
- [Flake8](https://flake8.pycqa.org/) for linting

### 3.2. Type Hints

Use type hints throughout the codebase:

```python
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

def get_patient(patient_id: UUID) -> Optional[Dict[str, Any]]:
    """
    Retrieve a patient by ID.
    
    Args:
        patient_id: The UUID of the patient
        
    Returns:
        The patient data or None if not found
    """
    # Implementation
```

### 3.3. Exception Handling

Follow these principles for exception handling:

- Use custom exception classes for domain-specific errors
- Catch specific exceptions, not generic `Exception`
- Re-raise exceptions with appropriate context
- Do not silence exceptions without good reason
- Log exceptions at appropriate levels

```python
class PatientNotFoundError(DomainError):
    """Raised when a patient is not found."""
    pass

async def get_patient(patient_id: UUID) -> Patient:
    try:
        patient = await patient_repository.find_by_id(patient_id)
        if not patient:
            raise PatientNotFoundError(f"Patient with ID {patient_id} not found")
        return patient
    except DatabaseError as e:
        logger.error(f"Database error when retrieving patient {patient_id}: {str(e)}")
        raise RepositoryError(f"Failed to retrieve patient {patient_id}") from e
```

## 4. Implementation Patterns

### 4.1. Dependency Injection

Use dependency injection to provide dependencies:

```python
# Dependencies are defined in app/api/dependencies
async def get_patient_repository(
    db: Database = Depends(get_database)
) -> PatientRepository:
    return SQLAlchemyPatientRepository(db)

# Dependencies are used in API endpoints
@router.get("/patients/{patient_id}", response_model=PatientResponse)
async def get_patient(
    patient_id: UUID,
    repository: PatientRepository = Depends(get_patient_repository),
    current_user: User = Depends(get_current_user)
):
    # Implementation
```

### 4.2. Repository Pattern

Implement repositories following this pattern:

```python
# Domain repository interface
class PatientRepository(Protocol):
    async def find_by_id(self, patient_id: UUID) -> Optional[Patient]:
        ...
    
    async def save(self, patient: Patient) -> Patient:
        ...

# Infrastructure implementation
class SQLAlchemyPatientRepository(PatientRepository):
    def __init__(self, db: Database):
        self.db = db
    
    async def find_by_id(self, patient_id: UUID) -> Optional[Patient]:
        stmt = select(PatientModel).where(PatientModel.id == patient_id)
        result = await self.db.execute(stmt)
        patient_model = result.scalar_one_or_none()
        if not patient_model:
            return None
        return self._to_domain(patient_model)
    
    async def save(self, patient: Patient) -> Patient:
        # Implementation
        
    def _to_domain(self, model: PatientModel) -> Patient:
        # Convert from ORM model to domain entity
```

### 4.3. Domain Services

Implement domain services as classes with clear responsibilities:

```python
class DigitalTwinAnalysisService:
    def __init__(
        self,
        digital_twin_repository: DigitalTwinRepository,
        ml_service: MLModelService
    ):
        self.digital_twin_repository = digital_twin_repository
        self.ml_service = ml_service
        
    async def analyze_trends(
        self,
        twin_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> TrendAnalysisResult:
        # Implementation
```

### 4.4. Application Services

Implement application services as orchestrators:

```python
class PatientService:
    def __init__(
        self,
        patient_repository: PatientRepository,
        digital_twin_service: DigitalTwinService,
        event_publisher: EventPublisher
    ):
        self.patient_repository = patient_repository
        self.digital_twin_service = digital_twin_service
        self.event_publisher = event_publisher
        
    async def create_patient(self, data: PatientCreateDTO) -> PatientDTO:
        # Validate input
        # Create patient entity
        # Save to repository
        # Create digital twin
        # Publish events
        # Return DTO
```

### 4.5. Event-Driven Communication

Domain events (defined in `domain/events/`) signal significant state changes. Handlers (typically in the application layer) subscribe to these events to perform side effects.

```python
# Define event (in domain/events/patient_events.py)
@dataclass(frozen=True)
class PatientRegistered(DomainEvent):
    patient_id: UUID
    registered_at: datetime = field(default_factory=datetime.now)

# Publish event (e.g., from application service)
await event_publisher.publish(
    PatientRegistered(patient_id=patient.id)
)

# Subscribe to event (e.g., in application/event_handlers.py)
@event_subscriber.subscribe(PatientRegistered)
async def handle_patient_registered(event: PatientRegistered):
    logger.info(f"Handling PatientRegistered event for patient {event.patient_id}")
    # ... implementation ...
```

### 4.6. Core Layer Components

The `core/` layer provides shared, foundational components:

- **`core/db.py`, `core/database_settings.py`**: Handles core database connection/session setup (as referenced in `40_Database_Management.md`).
- **`core/patterns/`**: Contains implementations of common design patterns (e.g., `observer.py`).
- **`core/models/`**: Defines core data structures, potentially used across layers (e.g., `token_models.py` for JWT).
- **`core/interfaces/`**: Defines fundamental interfaces used for dependency inversion (e.g., `jwt_service_interface.py`, potentially ML interfaces in `core/interfaces/ml/`).
- **`core/exceptions/`**: Provides a hierarchy of custom base exceptions (`base_exceptions.py`) and specific exception types for core concerns like JWT, authentication, and ML (`jwt_exceptions.py`, `auth_exceptions.py`, `ml_exceptions.py`).
- **`core/services/`**: Primarily contains core ML service definitions or interfaces within `core/services/ml/`.
- **`core/utils/`**: Offers common utility functions for tasks like validation (`validation.py`), date/time manipulation (`date_utils.py`), string operations (`string_utils.py`), data transformation (`data_transformation.py`), logging setup (`logging.py`), and potentially cloud interactions (`aws.py`).
- **`core/constants.py`**: Defines shared constants.

### 4.7. Infrastructure Service Adapters

*(Details TBD - Explain the approach for implementing adapters for external services, databases, messaging, etc., in `infrastructure/`, referencing specific examples like `infrastructure/database/` vs `infrastructure/persistence/`, `infrastructure/logging/`, `infrastructure/cache/`, `infrastructure/security/`, etc.)*

### 4.8. API Presentation Layer

*(Details TBD - Detail the implementation of FastAPI `dependencies/`, `middleware/`, and request/response `models/` (schemas) in `presentation/`)*

#### 4.7 Application Layer Logic

The Application Layer (`backend/app/application/`) orchestrates the application's use cases and business logic. It acts as an intermediary between the API/Presentation Layer and the Domain Layer, ensuring that domain entities and rules are handled correctly. It depends on abstractions (interfaces) defined within this layer or the Domain Layer, which are implemented by the Infrastructure Layer (e.g., repositories, external services).

Key subdirectories and their roles:

*   **`/use_cases`**: Organizes application logic by domain feature (e.g., `patient/`, `digital_twin/`, `analytics/`, `appointment/`). Use case handlers typically coordinate operations involving one or more Application Services and Repositories to fulfill a specific user story or feature requirement. *(Specific use case details TBD after examining individual files)*.
*   **`/services`**: Contains concrete implementations of application-specific services that encapsulate complex business logic or coordinate multiple domain actions. Identified services include:
    *   `PatientApplicationService`: Manages CRUD operations for `Patient` entities, including basic authorization checks. Depends on the `PatientRepository` interface. Responsible for mapping incoming data (likely DTOs or dicts) to domain entities and coordinating persistence.
    *   `DigitalTwinApplicationService`: Handles the lifecycle of `DigitalTwin` entities, including creation, retrieval by patient ID, and configuration updates. Depends on the `DigitalTwinRepository` interface.
    *   `TemporalNeurotransmitterService`: A sophisticated service responsible for generating, analyzing, simulating, and preparing visualization data for temporal neurotransmitter sequences. It interacts with `TemporalSequenceRepository`, potentially an `EventRepository` for auditing, uses `NeurotransmitterMapping` domain logic, and can integrate with an external `XGBoostService` (likely via an interface) for predictive modeling (e.g., treatment response simulation).
*   **`/interfaces`**: Defines contracts (abstract base classes) for dependencies that are external to the application core or require infrastructural implementation. This promotes the Dependency Inversion Principle. Identified interfaces include:
    *   `AIModelService`: An abstraction for interacting with AI/ML models, defining methods for prediction (`predict`) and retrieving model metadata/version. Implementations are expected in the Infrastructure Layer.
    *   `NotificationService`: An abstraction for sending various types of notifications (e.g., appointment reminders, secure messages) in a HIPAA-compliant manner and managing user preferences. Implementations (e.g., Email, SMS, Secure Messaging Platform adapters) belong in the Infrastructure Layer.
    *   **`/interfaces/repositories`**: Contains repository interfaces (defined in the Domain Layer but logically grouped here for dependency management) that define contracts for data persistence (e.g., `PatientRepository`, `DigitalTwinRepository`, `TemporalSequenceRepository`). Implementations reside in the Infrastructure Layer.
    *   **`/interfaces/services`**: Contains interfaces for other external or infrastructure-level services. *(Details TBD)*

*   **Data Transfer Objects (DTOs)**: While no dedicated `/dtos` directory was found directly under `/application`, DTOs are expected to be used for data exchange between layers (e.g., API -> Application, Application -> API). They might be defined within specific use case modules or closer to the API layer using Pydantic models. The current services often accept `Dict[str, Any]`, indicating potential areas for introducing strongly-typed DTOs for better validation and clarity.

This layer isolates domain logic from infrastructure concerns and provides clear entry points for the API layer to execute business workflows.

## 5. Security Implementation

### 5.1. Authentication

Implement authentication using JWT tokens:

```python
# Authentication dependency
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    jwt_service: JWTService = Depends(get_jwt_service)
) -> User:
    try:
        payload = jwt_service.decode_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise InvalidTokenError("Invalid token")
        
        # Fetch user from repository
        user = await user_repository.find_by_id(UUID(user_id))
        if user is None:
            raise UserNotFoundError("User not found")
            
        return user
    except JWTError:
        raise InvalidTokenError("Invalid token")
```

### 5.2. Authorization

Implement role-based authorization:

```python
def requires_permission(permission: Permission):
    def decorator(func):
        @wraps(func)
        async def wrapper(
            current_user: User = Depends(get_current_user),
            *args, **kwargs
        ):
            if not current_user.has_permission(permission):
                raise ForbiddenError("Insufficient permissions")
            return await func(current_user=current_user, *args, **kwargs)
        return wrapper
    return decorator

# Usage in API endpoint
@router.post("/patients")
@requires_permission(Permission.CREATE_PATIENT)
async def create_patient(
    data: PatientCreateRequest,
    current_user: User = Depends(get_current_user)
):
    # Implementation
```

### 5.3. PHI Protection

Implement PHI protection measures:

```python
# PHI encryption
class PHIEncryptionService:
    def __init__(self, encryption_key: bytes):
        self.encryption_key = encryption_key
        self.fernet = Fernet(encryption_key)
        
    def encrypt(self, data: str) -> str:
        return self.fernet.encrypt(data.encode()).decode()
        
    def decrypt(self, encrypted_data: str) -> str:
        return self.fernet.decrypt(encrypted_data.encode()).decode()

# Usage in repository
class EncryptedPatientRepository(PatientRepository):
    def __init__(
        self,
        repository: PatientRepository,
        encryption_service: PHIEncryptionService
    ):
        self.repository = repository
        self.encryption_service = encryption_service
        
    async def save(self, patient: Patient) -> Patient:
        # Encrypt PHI fields
        encrypted_patient = self._encrypt_phi(patient)
        return await self.repository.save(encrypted_patient)
        
    async def find_by_id(self, patient_id: UUID) -> Optional[Patient]:
        patient = await self.repository.find_by_id(patient_id)
        if not patient:
            return None
        return self._decrypt_phi(patient)
        
    def _encrypt_phi(self, patient: Patient) -> Patient:
        # Encrypt PHI fields
        
    def _decrypt_phi(self, patient: Patient) -> Patient:
        # Decrypt PHI fields
```

### 5.4. Bootstrap Module

The Bootstrap Module provides initialization utilities that ensure the project structure is properly set up during development and testing.

**Location**: `backend/bootstrap/`

**Key Components**:
- `sitecustomize_wrapper.py`: Ensures project-specific `sitecustomize` behavior is loaded
- `usercustomize_wrapper.py`: Provides user-specific customization for Python environment

**Purpose**:
- Maintains clean project structure by isolating initialization logic
- Ensures proper sys.path configuration during development and testing
- Provides consistent environment setup for all developers

**Usage**:
```python
# Automatic invocation during pytest and Python startup
# Manual activation if needed:
import backend.bootstrap.sitecustomize_wrapper
import backend.bootstrap.usercustomize_wrapper
```

**Configuration**:
- Wrappers are located in `backend/bootstrap/` directory
- They rely on `backend/sitecustomize` for core behavior
- No additional configuration is required

**Testing**:
- The bootstrap module is typically verified indirectly via the application's test harness
- No dedicated tests are required as it's a foundational component

**Deployment Considerations**:
- The bootstrap module is primarily for development and test environments
- Production deployments typically rely on container environment configuration instead

## 6. Script Utilities

The Novamind platform includes various utility scripts to facilitate development, testing, deployment, and operational tasks.

**Location**: `backend/scripts/`

### 6.1. Script Categories

- **Database Management**: Scripts for database initialization, migrations, and data seeding
- **Deployment**: Deployment automation for various environments
- **Model Pipelines**: Scripts related to ML model training, evaluation, and deployment
- **Development Tools**: Utilities to assist development workflows
- **Testing Utilities**: Support scripts for various testing scenarios

### 6.2. Key Scripts

- **Database Scripts**: 
  - `backend/scripts/db/init_db.sh`: Initialize the database schema
  - `backend/scripts/db/seed_data.py`: Populate test or demo data
  
- **Deployment Scripts**:
  - `backend/scripts/deploy/deploy_service.py`: Deploy services to various environments
  - `backend/scripts/deploy/rollback.sh`: Rollback to previous deployment

- **ML Scripts**:
  - `backend/scripts/neurotransmitters/`: Utilities for neurotransmitter modeling
  - `backend/scripts/QUANTUM_TEST.sh`: Stress test for model I/O

- **Development Scripts**:
  - Various helper scripts for environment setup and code generation

### 6.3. Usage Instructions

```bash
# List available scripts
ls backend/scripts/

# Execute a shell script
bash backend/scripts/<script>.sh

# Run Python scripts with help
python backend/scripts/<dir>/<script>.py --help

# Example: Seed development database
python backend/scripts/db/seed_data.py --env development
```

### 6.4. Testing

- Script tests are located in `backend/scripts/test/`
- Run tests with: `pytest backend/scripts/test/`

### 6.5. Known Limitations

- Documentation for some scripts may be incomplete
- Not all scripts follow a consistent CLI interface pattern
- Some scripts may have environment-specific dependencies

## 7. Application Entry Points

The Novamind platform uses specific entry point files to initialize and launch the FastAPI application.

**Key Entry Points**:
- `backend/main.py`: Primary entry point for the application
- `backend/app/main.py`: Core application initialization module

### 7.1. Entry Point Responsibilities

The entry point files handle several critical initialization tasks:

- Application configuration loading
- FastAPI instance creation and configuration
- Middleware registration (CORS, security, etc.)
- Exception handler setup
- API router registration
- ML model initialization
- Database connection setup
- Dependency injection container configuration

### 7.2. Configuration Sources

Entry points obtain configuration from various sources:
- Environment variables (e.g., `APP_ENV`, `DATABASE_URL`, ML model paths)
- Configuration files loaded by `app/core/config/settings.py`
- Command-line arguments passed to the ASGI server

### 7.3. Running the Application

```bash
# Development mode with auto-reload
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 7.4. Docker Deployment

```bash
# Build image
docker build -f backend/Dockerfile -t novamind-api .

# Run container
docker run -e DATABASE_URL=... -p 8000:8000 novamind-api
```

### 7.5. ML Component Initialization

The entry points trigger loading of machine learning components via the dependency injection container:

- XGBoost clinical prediction models
- PAT transformer for patient activity tracking
- MentalLLaMA33b for mental health insights
- LSTM for time-series analysis

### 7.6. Known Considerations

- Ensure environment variables are properly set before starting the application
- Consider implementing health check endpoints for production monitoring
- Configure logging levels and formats based on the environment

## 8. Common Tasks

### 8.1. Creating a New API Endpoint

Follow these steps to create a new API endpoint:

1. Define request and response models:

```python
# app/api/models/patient.py
class PatientCreateRequest(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: date
    gender: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "date_of_birth": "1980-01-01",
                "gender": "male"
            }
        }

class PatientResponse(BaseModel):
    id: UUID
    first_name: str
    last_name: str
    date_of_birth: date
    gender: Optional[str]
    created_at: datetime
```

2. Create the API route:

```python
# app/api/routes/patients.py
router = APIRouter(prefix="/patients", tags=["patients"])

@router.post(
    "/",
    response_model=PatientResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a patient"
)
async def create_patient(
    request: PatientCreateRequest,
    patient_service: PatientService = Depends(get_patient_service),
    current_user: User = Depends(get_current_user)
) -> PatientResponse:
    """
    Create a new patient.
    
    Requires permission: CREATE_PATIENT
    """
    # Authorize
    if not current_user.has_permission(Permission.CREATE_PATIENT):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create patients"
        )
    
    # Create patient
    patient_dto = await patient_service.create_patient(
        PatientCreateDTO(**request.dict())
    )
    
    # Return response
    return PatientResponse(**patient_dto.dict())
```

3. Include the router in the API:

```python
# app/api/__init__.py
from app.api.routes import patients

def setup_routers(app: FastAPI) -> None:
    app.include_router(patients.router, prefix="/api/v1")
```

### 8.2. Creating a New Domain Entity

1. Define the entity in the domain layer:

```python
# app/domain/entities/assessment.py
@dataclass
class Assessment:
    id: UUID
    patient_id: UUID
    clinician_id: UUID
    assessment_type: AssessmentType
    date: datetime
    results: Dict[str, Any]
    notes: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        patient_id: UUID,
        clinician_id: UUID,
        assessment_type: AssessmentType,
        results: Dict[str, Any],
        notes: Optional[str] = None
    ) -> "Assessment":
        return cls(
            id=uuid4(),
            patient_id=patient_id,
            clinician_id=clinician_id,
            assessment_type=assessment_type,
            date=datetime.now(),
            results=results,
            notes=notes
        )
```

2. Define the repository interface:

```python
# app/domain/repositories/assessment_repository.py
class AssessmentRepository(Protocol):
    async def save(self, assessment: Assessment) -> Assessment:
        ...
    
    async def find_by_id(self, assessment_id: UUID) -> Optional[Assessment]:
        ...
    
    async def find_by_patient_id(
        self,
        patient_id: UUID,
        limit: int = 100,
        offset: int = 0
    ) -> List[Assessment]:
        ...
```

3. Implement the repository:

```python
# app/infrastructure/repositories/sqlalchemy_assessment_repository.py
class SQLAlchemyAssessmentRepository(AssessmentRepository):
    def __init__(self, db: Database):
        self.db = db
    
    async def save(self, assessment: Assessment) -> Assessment:
        # Convert to ORM model and save
    
    async def find_by_id(self, assessment_id: UUID) -> Optional[Assessment]:
        # Query database and convert to domain entity
    
    async def find_by_patient_id(
        self,
        patient_id: UUID,
        limit: int = 100,
        offset: int = 0
    ) -> List[Assessment]:
        # Query database and convert to domain entities
```

### 8.3. Adding a New Migration

Use Alembic to manage database migrations:

```bash
# Create a new migration
alembic revision --autogenerate -m "Add assessment table"

# Apply migrations
alembic upgrade head

# Revert the last migration
alembic downgrade -1
```

## 9. Testing

### 9.1. Running Tests

```bash
# Run all tests
pytest

# Run specific tests
pytest tests/domain/test_patient.py

# Run tests with coverage
pytest --cov=app
```

### 9.2. Test Example

```python
# tests/domain/test_digital_twin.py
def test_digital_twin_creation():
    # Arrange
    patient_id = UUID("00000000-0000-0000-0000-000000000001")
    
    # Act
    digital_twin = DigitalTwin.create(patient_id)
    
    # Assert
    assert digital_twin.patient_id == patient_id
    assert digital_twin.version == 1
    assert isinstance(digital_twin.created_at, datetime)
    assert digital_twin.neurotransmitter_state == {}
    assert digital_twin.psychological_state == {}
```

## 10. Troubleshooting

### 10.1. Common Issues

- **Database connection issues**: Check database configuration and connection string
- **Authentication failures**: Verify JWT secret key and token expiration settings
- **Permission errors**: Check user roles and permissions in the database
- **Performance issues**: Enable SQL logging and check for N+1 query problems

### 10.2. Debugging

- Use logging for troubleshooting:

```python
logger.debug("Processing request: %s", request_id)
logger.info("User %s logged in", user_id)
logger.warning("Rate limit reached for user %s", user_id)
logger.error("Failed to process request: %s", str(e))
```

- Use FastAPI's debug mode during development:

```python
app = FastAPI(debug=True)
```

## 11. Deployment

### 11.1. Docker Deployment

The application can be deployed using Docker:

```bash
# Build the Docker image
docker build -t novamind-backend .

# Run the Docker container
docker run -p 8000:8000 novamind-backend
```

### 11.2. CI/CD Pipeline

The project uses GitHub Actions for CI/CD:

- **Continuous Integration**: Running tests, linting, and security checks on each push
- **Continuous Deployment**: Deploying to staging/production environments on specific branches

### 11.3. Environment Configuration

Configure each environment using environment variables:

- Development: `.env` file
- Staging/Production: Environment variables in deployment platform

## 12. Contributing

### 12.1. Pull Request Process

1. Create a feature branch from `develop`
2. Make your changes
3. Run tests and linting
4. Submit a pull request
5. Ensure CI checks pass
6. Get code review and approval

### 12.2. Documentation Standards

- Add docstrings to all functions, methods, and classes
- Update API documentation when changing endpoints
- Update domain documentation when changing domain models
- Keep README.md up to date with setup and usage instructions

## 13. Configuration Management

The Novamind platform uses a structured configuration system based on Pydantic Settings to manage application settings across environments.

### 13.1. Configuration Architecture

**Location**: `backend/app/config/`

**Key Components**:
- **Settings Class**: Primary configuration model that integrates all settings
- **ML Settings**: Sub-models for different ML components
- **Environment Loading**: Automatic loading from environment variables and `.env` files
- **Validation Logic**: Type checking and custom validators

### 13.2. Configuration Structure

The configuration system includes:

- **Core Settings**:
  - API configuration (prefixes, version, debug mode)
  - Security settings (JWT, authentication timeouts)
  - Database configuration (connection strings, pool settings)
  - CORS settings (allowed origins, methods)
  - Logging configuration (levels, formats)

- **ML-Specific Settings**:
  - `MentalLlamaSettings`: Configuration for MentalLLaMA33b model
  - `PATSettings`: Settings for PAT transformer
  - `XGBoostSettings`: Configuration for XGBoost models
  - `LSTMSettings`: Settings for LSTM biometric correlation model
  - `PHIDetectionSettings`: Configuration for PHI detection services

### 13.3. Usage Example

```python
from backend.app.config.settings import get_settings

# Get singleton settings instance
settings = get_settings()

# Access configuration values
database_url = settings.database_url
jwt_secret = settings.jwt_settings.secret_key
xgboost_model_path = settings.ml_settings.xgboost.model_path
```

### 13.4. Validation and Parsing

The configuration system performs several validation functions:

- Type validation for all settings
- Format validation for critical fields (URLs, paths)
- Dynamic assembly of connection strings
- Environment-specific defaults
- Secret value handling to prevent accidental exposure

### 13.5. Environment Variables

Key environment variables include:

```
# Core Settings
API_ENV=development|testing|production
API_DEBUG=true|false
DATABASE_URL=postgresql+asyncpg://user:pass@host:port/db

# Security
SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# ML Settings
MENTALLAMA_API_KEY=your-api-key
MENTALLAMA_PROVIDER=openai|anthropic|local
PAT_MODEL_PATH=/path/to/model
XGBOOST_MODEL_PATH=/path/to/xgboost
LSTM_BIOMETRIC_CORRELATION_MODEL_PATH=/path/to/lstm
```

### 13.6. Best Practices

- Use environment variables for all environment-specific configuration
- Never commit secrets or credentials to version control
- Use `.env.example` to document required environment variables
- Validate all configuration at startup
- Provide sensible defaults where appropriate
- Document all configuration options

### 13.7. Known Gaps

- Consider implementing configuration validation tests
- Improve error messages for missing required configuration
- Use secrets management service for production credentials

---

This implementation guide serves as a reference for developers working on the Novamind Digital Twin platform. For more detailed information, refer to the specific documentation for each component.

Last Updated: 2025-04-20

## 8. Demo Scripts

The `backend/app/demo/` directory contains scripts for demonstrating specific functionalities, such as:

- `enhanced_digital_twin_demo.py`: *(Purpose TBD)*
- `run_digital_twin_demo.py`: *(Purpose TBD)*

These scripts are intended for development and demonstration purposes only and should not be considered part of the production application deployment.

## 9. Contributing

*(Existing content...)*

### 4.8. Infrastructure Layer Components

This layer contains concrete implementations of interfaces defined in the Application and Domain layers, interacting with external concerns like databases, external APIs, ML models, and the operating system.

*Current Status: Implementations exist for configuration, security, and ML services. However, the core persistence layer (Repositories) relies on placeholders or mocks.*

**Key Subdirectories and Responsibilities:**

*   **`persistence/`**: Handles data storage and retrieval.
    *   **`persistence/sqlalchemy/`**: Contains the intended primary persistence implementations using SQLAlchemy.
        *   **`repositories/`**: Includes concrete repository implementations like `PatientRepository`, `UserRepository`, `DigitalTwinRepositoryImpl`.
        *   **`config/`**: (Assumed based on `app_config.py`) Likely contains database connection setup (e.g., `Database` class referenced in `app_config.py`).
        *   **DISCREPANCY:** The `DigitalTwinRepositoryImpl` (`persistence/sqlalchemy/repositories/digital_twin_repository.py`) is currently a **placeholder** with non-functional methods (`pass`). Other SQLAlchemy repositories might also be placeholders.
    *   **`repositories/` (at `infrastructure/repositories/`)**: Contains **mock implementations** (`MockDigitalTwinRepository`, `MockPatientRepository`) using in-memory storage, likely for testing or development purposes. It is crucial to determine whether the application currently runs against these mocks or the non-functional SQLAlchemy placeholders.

*   **`ml_services/`**: Provides concrete implementations for ML model interactions defined by interfaces in `app/domain/interfaces/ml_services.py`.
    *   Organized by domain (e.g., `symptom_forecasting/`, `biometric_correlation/`).
    *   Contains service implementations (e.g., `SymptomForecastingServiceImpl`) that load and run ML models (e.g., `.pkl` files).
    *   Adapters (`infrastructure/ml/adapters/`) connect these implementations to the application layer.

*   **`security/`**: Implements cross-cutting security concerns.
    *   Contains modules for:
        *   `auth/`: Authentication (`AuthenticationService`).
        *   `jwt/`: JWT handling (`JWTService`).
        *   `encryption/`: Data encryption (`BaseEncryptionService`).
        *   `password/`: Password hashing and verification (`PasswordHandler`).
        *   `rbac/`: Role-Based Access Control (`RBACService`).
        *   `rate_limiting/`: Request rate limiting (`DistributedRateLimiter`).
        *   `audit/`: Audit logging (`AuditLogger`).
        *   `phi/`: PHI sanitization and redaction utilities (`LogSanitizer`, `PHIFormatter`, `PHIRedactionHandler`). *(Note: Effectiveness depends on integration, e.g., previously noted disabled PHI middleware)*.

*   **`config/`**: Manages application and service configuration loading and dependency setup.
    *   `app_config.py`: Central configuration class, responsible for instantiating and wiring components like repositories (currently pointing to placeholder/real implementations) and ML adapters into services.
    *   `ml_service_config.py`: Specific configuration class for setting up ML services and adapters, including model path management.

*   **`services/`**: (Presence noted, content not explored in detail) Potentially holds implementations for other external service interfaces (e.g., notification service, external API clients).
*   **`logging/`**: (Presence noted, content not explored in detail) Likely contains logging configuration and setup.
*   **`aws/`, `messaging/`, `factories/`, `di/`, `models/`, `cache/`, `external/`**: (Presence noted, content not explored in detail) These directories suggest infrastructure for cloud services, messaging queues, object factories, dependency injection helpers, data models (potentially ORM models?), caching, and other external integrations, requiring further investigation.

**Discrepancies & Areas for Clarification:**

*   The most critical discrepancy is the state of the **persistence layer**. The application configuration references SQLAlchemy implementations, but the core `DigitalTwinRepositoryImpl` is a placeholder. Mock repositories exist elsewhere. This needs immediate resolution to understand how data is actually persisted (if at all).
*   The purpose of duplicate directories like `infrastructure/repositories/` vs `infrastructure/persistence/sqlalchemy/repositories/`, and `infrastructure/ml/` vs `infrastructure/ml_services/` should be clarified and potentially consolidated.
*   The implementation status of interfaces like `NotificationService` needs verification within `infrastructure/services/` or `infrastructure/external/`.
*   The actual integration and configuration of security components (especially Audit Logging and PHI handling) within the API/application flow needs confirmation.
