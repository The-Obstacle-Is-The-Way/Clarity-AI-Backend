# Project Structure Overview

## Introduction

The Clarity AI Backend implements a revolutionary psychiatric digital twin platform built on a mathematically elegant architecture. The project structure directly mirrors our clean architecture principles, with each directory representing a distinct architectural layer.

This document outlines the organization of the codebase, explains the rationale behind key structural decisions, and serves as a navigation guide for developers.

## Root Structure

The repository is organized with the following top-level directories:

```plaintext
/
├── alembic/              # Database migration tooling and scripts
├── app/                  # Core application codebase (detailed below)
├── bootstrap/            # System initialization and startup scripts
├── deployment/           # Deployment configuration and infrastructure
├── docs/                 # Comprehensive documentation
├── scripts/              # Utility scripts and tools
├── tests/                # Integration and end-to-end tests
├── main.py               # Application entry point
└── pyproject.toml        # Python project configuration
```

## Application Core (`app/`)

The `app/` directory contains the application codebase organized into clean architecture layers. Each directory represents a distinct layer with specific responsibilities and dependencies.

```plaintext
app/
├── application/          # Application use cases and orchestration
├── core/                 # Cross-cutting concerns and interfaces
├── domain/               # Core business logic and entities
├── infrastructure/       # Technical implementations and adapters
├── presentation/         # API endpoints and controllers
└── tests/                # Unit and integration tests
```

## Layer-by-Layer Breakdown

### Domain Layer (`app/domain/`)

The foundational layer containing pure business logic with no external dependencies:

```plaintext
domain/
├── entities/             # Core business objects and psychiatric models
├── enums/                # Domain-specific enumerated types
├── events/               # Domain events for event-driven architecture
├── exceptions/           # Domain-specific exceptions
├── interfaces/           # Repository and service interfaces (being consolidated to core)
├── ml/                   # Machine learning domain concepts
├── repositories/         # Data access abstractions (being consolidated)
├── services/             # Business logic services
├── utils/                # Pure domain utilities
└── value_objects/        # Immutable domain values
```

**Organizational Principles:**

- Contains no framework, database, or external service dependencies
- Represents pure psychiatric modeling concepts
- Defines interfaces that other layers implement (moving to core)
- Follows Domain-Driven Design principles

### Application Layer (`app/application/`)

Orchestrates domain logic into use cases and application workflows:

```plaintext
application/
├── dtos/                 # Data Transfer Objects for boundary crossing
├── interfaces/           # Application-specific interfaces
├── security/             # Application-level security services
├── services/             # Application orchestration services
└── use_cases/            # Distinct clinical and operational use cases
```

**Organizational Principles:**

- Depends only on domain layer, not infrastructure
- Orchestrates domain objects to implement use cases
- Defines input/output boundaries via DTOs
- Handles transactional boundaries

### Infrastructure Layer (`app/infrastructure/`)

Provides concrete implementations of interfaces defined in domain and core layers:

```plaintext
infrastructure/
├── logging/              # Logging implementations
├── ml/                   # Machine learning infrastructure
├── persistence/          # Database and storage implementations
│   ├── sqlalchemy/       # SQLAlchemy-specific implementation
│   │   ├── mappers/      # ORM mappings between domain and DB
│   │   ├── models/       # Database models
│   │   └── repositories/ # Repository implementations
├── rate_limiting/        # Rate limiting implementations
├── security/             # Security implementations
└── services/             # External service integrations
```

**Organizational Principles:**

- Implements interfaces defined in domain and core layers
- Contains all I/O, database, and external API logic
- Isolates technical implementations from business logic
- Provides adapters for external services

### Presentation Layer (`app/presentation/`)

Manages API endpoints, request handling, and responses:

```plaintext
presentation/
├── api/                  # API routes and endpoints
│   ├── dependencies/     # FastAPI dependency providers
│   └── v1/               # API version 1
│       ├── endpoints/    # API route handlers
│       └── routes/       # Route definitions
├── middleware/           # Request processing middleware
└── schemas/              # Pydantic schemas for validation
```

**Organizational Principles:**

- Transforms external requests into application commands
- Handles HTTP-specific concerns
- Validates input via Pydantic schemas
- Serializes domain models to API responses
- Uses dependency injection for service resolution

### Core Layer (`app/core/`)

Contains cross-cutting concerns and architectural scaffolding:

```plaintext
core/
├── config/               # System configuration management
├── domain/               # Core domain types used across layers
├── interfaces/           # Consolidated interface definitions
│   ├── repositories/     # Repository interface definitions
│   └── services/         # Service interface definitions
└── security/             # Security primitives and abstractions
```

**Organizational Principles:**

- Provides interfaces implemented across layers
- Defines cross-cutting concerns like configuration
- Contains abstractions that bridge architectural boundaries
- Defines security and authentication foundations

## Testing Structure (`app/tests/`)

Tests are organized to mirror the application structure:

```plaintext
tests/
├── conftest.py           # Test fixtures and configuration
├── integration/          # Integration tests across layers
├── unit/                 # Isolated unit tests
│   ├── application/      # Application layer tests
│   ├── domain/           # Domain layer tests
│   ├── infrastructure/   # Infrastructure layer tests
│   └── presentation/     # Presentation layer tests
└── utils/                # Test utilities and helpers
```

**Organizational Principles:**

- Tests are organized per layer and component
- Unit tests depend only on the layer being tested
- Integration tests verify interactions between layers
- Fixtures provide controlled test environments

## File Naming Conventions

The codebase follows consistent naming conventions:

1. **Python Modules**: Snake case (e.g., `user_repository.py`)
2. **Interface Definitions**: Prefixed with "I" or suffixed with "_interface" (being standardized)
3. **Implementation Classes**: Descriptive names with implementation detail (e.g., `SQLAlchemyUserRepository`)
4. **Test Files**: Prefixed with `test_` (e.g., `test_user_service.py`)

## Architectural Enforcement

The project structure enforces clean architecture through:

1. **Import Constraints**: Inner layers cannot import from outer layers
2. **Interface Definitions**: Abstractions defined in inner layers, implementations in outer layers
3. **Dependency Injection**: Dependencies provided via interfaces, not concrete implementations

## Current Structural Issues

The following structural issues are being addressed:

1. **Interface Duplication**: Some interfaces exist in both `app/core/interfaces/` and `app/domain/interfaces/`
2. **Missing Components**: Some referenced components are missing (e.g., middleware implementations)
3. **Inconsistent Naming**: Varying patterns for interfaces and implementations

## Conclusion

The Clarity AI Backend's project structure is designed to enable a mathematically elegant implementation of clean architecture, separating concerns into distinct layers while maintaining clear dependencies between them. This structure provides a solid foundation for the revolutionary psychiatric digital twin platform, enabling teams to develop components in parallel while maintaining architectural integrity.

By organizing the codebase according to clean architecture principles, we ensure that the system remains adaptable to changing requirements, testable at all levels, and capable of evolving to meet emerging psychiatric modeling needs.
