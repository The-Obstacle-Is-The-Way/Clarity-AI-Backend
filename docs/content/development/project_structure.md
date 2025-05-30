# Project Structure

This document provides a comprehensive overview of the Clarity-AI Backend codebase structure, organized according to clean architecture principles.

## Root Directory Structure

```
Clarity-AI-Backend/
├── app/                    # Main application code
├── alembic/                # Database migrations
├── artifacts/              # Generated artifacts
├── docs/                   # Documentation
├── deployment/             # Deployment configurations
├── logs/                   # Application logs
├── scripts/                # Utility scripts
├── tasks/                  # Task management
├── tests/                  # External test resources
├── tools/                  # Development tools
├── .vale/                  # Documentation linting rules
├── main.py                 # Application entry point
├── conftest.py             # Pytest configuration
├── pyproject.toml          # Project configuration
├── requirements.txt        # Dependencies
└── README.md               # Project overview
```

## Application Architecture

The application follows clean architecture principles with clear separation of concerns:

```
app/
├── core/                  # Cross-cutting concerns and core interfaces
├── domain/                # Business domain layer
├── application/           # Application services and use cases
├── infrastructure/        # External interfaces implementation
├── presentation/          # API and interface layer
├── tests/                 # Application tests
├── config/                # Application configuration
└── security/              # Security components
```

## Detailed Layer Breakdown

### Core Layer

The core layer contains interfaces, base classes, and cross-cutting concerns that are used across the application:

```
core/
├── config/                # Application configuration
├── constants/             # Global constants
├── dependencies/          # Core dependencies
├── domain/                # Core domain entities and interfaces
│   ├── entities/          # Base entity models
│   │   ├── ml/            # Machine learning entities
│   │   └── phi/           # Protected health information entities
│   ├── enums/             # Domain enumerations
│   ├── exceptions/        # Domain exceptions
│   └── types/             # Domain type definitions
├── enums/                 # Global enumerations
├── errors/                # Error definitions
├── exceptions/            # Base exceptions
├── interfaces/            # Core interfaces
│   ├── repositories/      # Repository interfaces
│   ├── security/          # Security interfaces
│   └── services/          # Service interfaces
│       ├── audit/         # Audit service interfaces
│       ├── jwt/           # JWT service interfaces
│       ├── ml/            # Machine learning service interfaces
│       └── rate_limiting/ # Rate limiting service interfaces
├── security/              # Security components
│   ├── middleware/        # Security middleware
│   └── rate_limiting/     # Rate limiting implementation
└── services/              # Core services
    ├── aws/               # AWS service integrations
    ├── encryption/        # Encryption services
    └── ml/                # Machine learning services
        ├── digital_twin/  # Digital twin services
        ├── mentallama/    # MentaLLaMA services
        ├── pat/           # Psychiatric Analysis Tool services
        ├── phi/           # PHI-related services
        ├── providers/     # ML provider integrations
        └── xgboost/       # XGBoost services
```

### Domain Layer

The domain layer contains business entities, value objects, and domain services:

```
domain/
├── entities/              # Business entities
│   ├── digital_twin/      # Digital twin entities
│   └── ml/                # ML-specific entities
├── enums/                 # Domain-specific enumerations
├── events/                # Domain events
├── exceptions/            # Domain-specific exceptions
├── interfaces/            # Domain interfaces
│   ├── ml/                # ML interfaces
│   │   └── pharmacogenomics/ # Pharmacogenomics interfaces
│   └── repositories/      # Repository interfaces
├── ml/                    # Machine learning domain components
├── models/                # Domain models
├── repositories/          # Repository definitions
├── schemas/               # Schema definitions
├── services/              # Domain services
│   └── mocks/             # Mock services for testing
├── utils/                 # Domain utilities
└── value_objects/         # Immutable value objects
```

### Application Layer

The application layer orchestrates the domain entities to perform use cases:

```
application/
├── dtos/                  # Data transfer objects
├── interfaces/            # Application interfaces
│   ├── repositories/      # Repository interfaces
│   └── services/          # Service interfaces
├── security/              # Application security services
├── services/              # Application services
│   └── ml/                # ML application services
└── use_cases/             # Business use cases
    ├── analytics/         # Analytics use cases
    ├── appointment/       # Appointment management use cases
    ├── digital_twin/      # Digital twin use cases
    └── patient/           # Patient management use cases
```

### Infrastructure Layer

The infrastructure layer provides implementations of interfaces defined in the core, domain, and application layers:

```
infrastructure/
├── aws/                   # AWS integrations
├── cache/                 # Caching implementations
├── config/                # Infrastructure configurations
├── database/              # Database implementations
│   └── models/            # ORM models
├── di/                    # Dependency injection
├── external/              # External service integrations
│   ├── aws/               # AWS integrations
│   └── openai/            # OpenAI integrations
├── factories/             # Factory implementations
├── integrations/          # Third-party integrations
│   └── aws/               # AWS integration specifics
├── logging/               # Logging implementation
├── ml_services/           # Machine learning services
│   ├── biometric_correlation/ # Biometric correlation
│   ├── digital_twin_integration/ # Digital twin integration
│   └── pharmacogenomics/  # Pharmacogenomics
├── persistence/           # Data persistence
│   ├── filters/           # Query filters
│   ├── repositories/      # Repository implementations
│   └── sqlalchemy/        # SQLAlchemy implementation
│       ├── models/        # SQLAlchemy models
│       ├── repositories/  # SQLAlchemy repositories
│       └── types/         # Custom SQLAlchemy types
├── security/              # Security implementations
│   ├── audit/             # Security audit
│   └── jwt/               # JWT implementation
└── services/              # Infrastructure services
    └── ml/                # ML service implementations
        ├── mentallama/    # MentaLLaMA implementation
        ├── pat/           # PAT implementation
        └── xgboost/       # XGBoost implementation
```

### Presentation Layer

The presentation layer handles HTTP requests and responses:

```
presentation/
├── api/                   # API components
│   ├── adapters/          # API adapters
│   ├── dependencies/      # API dependencies
│   ├── models/            # API models
│   ├── routers/           # API routers
│   │   └── ml/            # ML-specific routers
│   ├── schemas/           # API schemas
│   └── v1/                # API v1
│       ├── dependencies/  # v1 dependencies
│       │   └── biometric_alert/ # Biometric alert dependencies
│       ├── endpoints/     # v1 endpoints
│       ├── routes/        # v1 routes
│       │   └── ml/        # ML-specific routes
│       └── schemas/       # v1 schemas
├── dependencies/          # Presentation dependencies
├── middleware/            # HTTP middleware
└── schemas/               # Presentation schemas
```

## Test Organization

Tests are organized to mirror the application structure:

```
app/tests/
├── api/                   # API tests
│   ├── integration/       # API integration tests
│   ├── routes/            # API route tests
│   └── unit/              # API unit tests
├── application/           # Application layer tests
│   └── presentation/      # Presentation layer tests
│       └── api/           # API tests
│           ├── dependencies/ # API dependency tests
│           ├── docs/         # API documentation tests
│           ├── middleware/   # Middleware tests
│           ├── routers/      # Router tests
│           ├── schemas/      # Schema tests
│           └── v1/           # v1 API tests
│               ├── dependencies/ # v1 dependency tests
│               ├── endpoints/    # v1 endpoint tests
│               └── schemas/      # v1 schema tests
├── conftest/              # Test configuration
├── fixtures/              # Test fixtures
├── integration/           # Integration tests
│   └── api/               # API integration tests
│       └── v1/            # v1 API integration tests
│           └── endpoints/ # v1 endpoint integration tests
├── mocks/                 # Mock objects
├── security/              # Security tests
│   └── api/               # Security API tests
├── standalone/            # Standalone tests
│   └── api/               # Standalone API tests
└── unit/                  # Unit tests
    ├── api/               # API unit tests
    ├── application/       # Application unit tests
    ├── core/              # Core unit tests
    ├── domain/            # Domain unit tests
    ├── infrastructure/    # Infrastructure unit tests
    ├── presentation/      # Presentation unit tests
    └── services/          # Services unit tests
```

## Code Organization Principles

The Clarity-AI Backend follows these organizational principles:

1. **Clean Architecture**: Clear separation between domain, application, infrastructure, and presentation layers
2. **Dependency Rule**: Dependencies point inward (presentation → application → domain)
3. **Interface Segregation**: Interfaces are defined at the core/domain level and implemented in the infrastructure layer
4. **Dependency Injection**: Dependencies are injected rather than instantiated directly
5. **Domain-Driven Design**: Business logic is encapsulated in the domain layer
6. **SOLID Principles**: Single responsibility, open/closed, Liskov substitution, interface segregation, dependency inversion

## File Naming Conventions

- **Modules**: snake_case (e.g., `digital_twin_service.py`)
- **Classes**: PascalCase (e.g., `DigitalTwinService`)
- **Functions/Methods**: snake_case (e.g., `create_digital_twin()`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_TOKEN_AGE`)
- **Type Variables**: PascalCase (e.g., `EntityT`)
- **Test Files**: `test_` prefix (e.g., `test_digital_twin_service.py`)

## Additional Resources

For more detailed information about specific components:

- [Architecture Overview](../architecture/overview.md)
- [API Documentation](../api/README.md)
- [Development Guide](../development/README.md)
- [Test Strategy](../development/test_strategy.md)