# Clarity AI Backend - Database Documentation

## 1. Overview

The database is a critical component of the Clarity AI Backend, responsible for persistent storage of all core application data, including user information, patient data (handled with extreme care according to HIPAA), digital twin configurations, interaction logs, and potentially other domain-specific entities. This document outlines the technology, configuration, schema management, and considerations for both production and testing environments.

### 1.1 Current State Assessment (May 2025)

Our recent architectural audit and refactoring has revealed several critical findings regarding the database layer:

1. **Consolidated Base Class**: We have established a canonical base class definition in `app/infrastructure/database/base_class.py` that serves as the single source of truth for all SQLAlchemy models, resolving registry and metadata conflicts.

2. **Relationship Modeling Issues**: We identified and fixed problematic bidirectional relationships between key models (notably User and Provider), eliminating redundant foreign key specifications and circular reference issues.

3. **Cross-Database Compatibility**: We've implemented platform-independent GUID/UUID handling to ensure consistent behavior between PostgreSQL (production) and SQLite (testing).

4. **Clean Architecture Progress**: We've begun aligning the database layer with Clean Architecture principles by properly separating infrastructure concerns from domain logic, though further improvements are needed.

## 2. Technology Stack

* Production Database: PostgreSQL (Assumed standard, requires confirmation based on `ASYNC_DATABASE_URI`)
* Testing Database: SQLite (In-memory)
* ORM: SQLAlchemy (Asynchronous using `asyncio` extension)
* Migrations: Alembic (Assumed standard for SQLAlchemy schema migrations)
* Driver: `asyncpg` (for PostgreSQL), `aiosqlite` (for SQLite)

## 3. Production Configuration

* Connection URI: Defined by the `ASYNC_DATABASE_URI` environment variable, loaded via `app.core.config.Settings`.
  * The system automatically converts standard `DATABASE_URL` to async version using `ASYNC_DATABASE_URI` (e.g., `sqlite:///` to `sqlite+aiosqlite:///`).
* Initialization: The SQLAlchemy `AsyncEngine` and session factory (`sessionmaker`) are created during application startup within the `lifespan` context manager in `app/app_factory.py`.
* State Management: The engine and session factory are stored in the `FastAPI` application state (`app.state.db_engine`, `app.state.db_session_factory`) for accessibility.
* Session Management:
  * A request-scoped `AsyncSession` is provided via the `get_async_session` dependency (`app.infrastructure.database.session.get_async_session`).
  * This dependency retrieves the session factory from `request.app.state` and yields a session, ensuring proper session handling per request.
  * Error handling within the dependency ensures sessions are closed/rolled back appropriately.

## 4. Testing Configuration (`app/tests/conftest.py`)

* Database: Uses an in-memory SQLite database (`sqlite+aiosqlite:///:memory:`) configured via `test_settings` overriding the main settings.
* Model Loading: 
  * The test configuration now explicitly calls `ensure_all_models_loaded()` before creating tables.
  * Models are validated with `validate_models()` to ensure proper mapping.
* Engine (`test_db_engine` fixture):
  * Function-scoped `AsyncEngine` for clean test isolation.
  * Uses `StaticPool` suitable for SQLite in-memory databases.
  * Handles table creation (`Base.metadata.create_all`) within a transaction before tests run and proper disposal after completion.
* Session (`db_session` fixture):
  * Function-scoped `AsyncSession` with transaction control.
  * Begins a transaction at the start of each test.
  * Yields the session to the test function.
  * Commits on success or rolls back on exception, ensuring proper test isolation.
* Dependency Override (in integration test fixtures):
  * Test-specific instances of the FastAPI application are created with proper dependency overrides.
  * The application's `get_async_session` dependency is overridden with test-specific session.
  * This ensures tests operate within controlled transactions for proper isolation.

### 4.1 Critical Test Database Issues Analysis

#### Driver Configuration Issues
The application exhibits a critical mismatch in database driver configuration between production and test environments:

* **Production Configuration**: The `settings.DATABASE_URL` is set to `sqlite:///./novamind.db` in `app.core.config.settings`
* **Required Async Configuration**: The database access layer requires an async SQLite driver, specifically `sqlite+aiosqlite:///`
* **Error Impact**: Tests fail with `ValueError: Database URL 'sqlite:///./novamind.db' does not seem to use a supported async driver`
* **Solution**: Tests must override `DATABASE_URL` with `sqlite+aiosqlite:///./test_db.sqlite3` or use in-memory SQLite (`sqlite+aiosqlite:///:memory:`)

#### Repository Architecture Inconsistencies

The project has multiple repository interfaces with naming discrepancies that violate Clean Architecture principles:

1. **Interface Duplication**:
   * Core layer: `app.core.interfaces.repositories.user_repository_interface.IUserRepository` with method `get_by_id`
   * Domain layer: `app.domain.repositories.user_repository.UserRepository` with method `get_by_id`

2. **Implementation Binding**:
   * `app.infrastructure.persistence.sqlalchemy.repositories.user_repository.SQLAlchemyUserRepository` implements the domain interface `UserRepository`, not the core interface `IUserRepository`
   * Binds to `UserRepositoryInterface` imported from the domain layer, violating Clean Architecture principles

3. **Method Naming Inconsistency**:
   * Test code attempts to access `get_user_by_id` but implementations have `get_by_id`
   * This naming mismatch causes `AttributeError: 'SqlAlchemyUserRepository' object has no attribute 'get_user_by_id'`

### 4.2 UUID/GUID Standardization

A critical issue in the database architecture was the inconsistent handling of UUID fields across models:

1. **Inconsistent UUID Implementation**:
   * Different models used different approaches for UUID fields (String(36), native UUID, etc.)
   * This caused ORM mapping errors like `UnmappedColumnError: No column users.id is configured on mapper Mapper[User(users)]`

2. **Standardized GUID Solution**:
   * Created a platform-independent `GUID` type in `app/infrastructure/persistence/sqlalchemy/types.py`
   * This type handles both PostgreSQL's native UUID type and SQLite's string-based implementation
   * Used consistently for all ID fields across all models

3. **Cross-Database Compatibility**:
   * The `GUID` type automatically adapts to the database backend (PostgreSQL or SQLite)
   * Ensures proper UUID-to-string conversion for SQLite and native UUID handling for PostgreSQL
   * Preserves the UUID semantics regardless of database backend

### 4.3 Model Registration and Validation

To ensure consistent model definitions and prevent mapping conflicts, we've implemented a model registration and validation system:

1. **Centralized Model Registry**:
   * All models are now registered with a central registry in `app/infrastructure/database/base_class.py`
   * Registration happens automatically when models inherit from the canonical `Base` class
   * The registry provides visibility into all models and their properties

2. **Model Validation**:
   * The `validate_models()` function examines all registered models to ensure they:
     * Have a defined `__tablename__`
     * Have a proper primary key
     * Are correctly mapped to the underlying database tables
   * Validation runs during application startup and before test suite execution

3. **Base Model Benefits**:
   * Common utility methods like `to_dict()` and `from_dict()` provided by `BaseModel`
   * Standard mixins for timestamps (`TimestampMixin`) and audit fields (`AuditMixin`)
   * Consistent approach to model definition across the application

#### Dependency Injection Complexity

The DI system creates significant complexity for testing:

1. **Multi-layered Injection**:
   * `app_instance.dependency_overrides[get_repository_instance]` requires overriding at a lower level than expected
   * Repository factories in `app.infrastructure.di.container.DIContainer._repository_factories` handle session injection
   * Simple dependency overrides in tests don't propagate through all layers

2. **Container Singleton Pattern**:
   * Global container instance in `app.infrastructure.di.container` persists between tests
   * Container isn't properly reset for each test, leading to potential state leakage
   * Manual container reset is needed via `reset_container()` to ensure clean test isolation

#### Testing Best Practices

To properly test repository-dependent code:

1. **Precise Interface Mocking**:
   * Mock the exact interface being used by the application code
   * Ensure mocks implement all required methods with matching signatures

2. **Multi-level Dependency Overrides**:
   * Override at the correct dependency level (repository instance provider)
   * Consider direct module patching for deeply embedded dependencies

3. **Proper Repository Factory Registration**:
   * Register a mock repository factory function that returns the mock for any session
   * Ensure factory functions match the expected signature: `Callable[[AsyncSession], T]`

## 5. Schema Management (PRD Requirement)

* Definition: Database schema (tables, columns, constraints, relationships) is defined using SQLAlchemy models located primarily within `app/infrastructure/persistence/sqlalchemy/models/`.
* Base Model: All models MUST inherit from the canonical declarative base defined in `app/infrastructure/database/base_class.py` (`Base`).

### 5.1 Model Definition Best Practices

Based on our recent architectural refactoring, we've established these best practices for model definitions:

1. **Single Source of Truth**:
   * Always import `Base` from `app/infrastructure/database/base_class.py`
   * Never create local base classes or metadata instances
   * Use the `register_model` decorator for any models that don't inherit from `Base`

2. **Relationship Definition**:
   * Avoid redundant `foreign_keys` specifications when SQLAlchemy can infer them
   * For bidirectional relationships, define `back_populates` on both sides instead of `backref`
   * Add proper cascade behavior for parent-child relationships
   * Avoid circular `viewonly=True` in bidirectional relationships

3. **Type Handling**:
   * Use the `GUID` type from `app/infrastructure/persistence/sqlalchemy/types.py` for all UUID fields
   * Use cross-database compatible types like `JSONEncodedDict` instead of PostgreSQL-specific `JSONB`

4. **Documentation**:
   * Add docstrings to all model classes explaining their purpose
   * Add comments to columns with business significance or constraints
   * Document relationships with comments explaining the domain relationship

* Migrations (Alembic - Recommended):
  * Alembic should be used to manage schema changes incrementally and reliably.
  * Requires `alembic.ini` configuration file.
  * Requires `alembic/env.py` script configured to connect to the database and target the `Base.metadata`.
  * Migrations are generated using `alembic revision --autogenerate -m "Description"`.
  * Migrations are applied using `alembic upgrade head`.

## 6. Data Integrity & Constraints (PRD Requirement)

* Primary Keys: Enforced by SQLAlchemy models.
* Foreign Keys: Defined in models to maintain relational integrity.
* Unique Constraints: Applied to relevant fields (e.g., emails, usernames) via model definitions.
* CHECK Constraints: Used for enforcing specific value rules where applicable.
* Non-Nullable Fields: Defined using `nullable=False` in model columns.
* HIPAA: Robust data integrity is fundamental for HIPAA compliance, preventing data corruption and ensuring accurate patient records.

## 7. Performance Considerations (PRD Requirement)

* Indexing: Define appropriate indexes on columns frequently used in `WHERE` clauses, `JOIN` conditions, and `ORDER BY` clauses. Analyze common query patterns to determine optimal indexing strategies.
* Query Optimization: Write efficient SQLAlchemy queries. Avoid loading unnecessary columns (`select(Model.col)` vs `select(Model)`). Use eager loading (`selectinload`, `joinedload`) judiciously where appropriate to avoid N+1 query problems.
* Connection Pooling: Handled automatically by the SQLAlchemy `AsyncEngine`.

## 8. Security Considerations (PRD Requirement)

* Credentials: Database connection credentials (username, password, host, port, database name) MUST be managed via environment variables (`ASYNC_DATABASE_URI`) and NEVER hardcoded in the source code.
* Encryption at Rest: Leverage PostgreSQL's native encryption capabilities or filesystem-level encryption on the database server.
* Encryption in Transit: Ensure TLS/SSL is enforced for connections between the application server and the database server (configured in PostgreSQL and potentially in the connection string).
* Input Validation: Use Pydantic models for request/data validation BEFORE attempting database operations to prevent invalid data persistence.
* SQL Injection: Prevented by the use of SQLAlchemy ORM, which generates parameterized queries.
* Principle of Least Privilege: The database user configured in `ASYNC_DATABASE_URI` should only have the minimum necessary permissions required for the application to function.

## 9. Implementation Checklist

### 9.1 Completed Items

* [x] Models: Define all required SQLAlchemy models in `app/infrastructure/persistence/sqlalchemy/models/`, inheriting from `Base`.
* [x] Base Class Consolidation: Established a canonical base class in `app/infrastructure/database/base_class.py`.
* [x] Model Registration: Implemented a system for tracking and validating all SQLAlchemy models.
* [x] Cross-Database Compatibility: Implemented platform-independent GUID/UUID handling.
* [x] Relationship Fixes: Corrected bidirectional relationships between User and Provider models.
* [x] Configuration: Set up `ASYNC_DATABASE_URI` environment variable for development, staging, and production environments.
* [x] Security Review - No hardcoded credentials: Confirmed all database credentials are handled via environment variables.

### 9.2 In Progress Items

* [ ] Constraints: Add necessary `UniqueConstraint`, `CheckConstraint`, `ForeignKeyConstraint`, `Index` definitions within models.
* [ ] Test Verification: Ensure all tests pass, confirming the `conftest.py` setup correctly manages test database sessions and isolation (Addressing SQLAlchemy model issues).
* [ ] Documentation: Keep this document updated as the database schema or configuration evolves.

### 9.3 Pending Items

* [ ] Alembic Setup:
  * [ ] Initialize Alembic (`alembic init alembic`).
  * [ ] Configure `alembic.ini` (set `sqlalchemy.url`).
  * [ ] Configure `alembic/env.py` (target `Base.metadata`, import models).
* [ ] Initial Migration:
  * [ ] Generate initial schema migration (`alembic revision --autogenerate -m "Initial schema setup"`).
  * [ ] Apply the migration (`alembic upgrade head`).
* [ ] Indexing: Review critical query patterns and add necessary indexes to models.
* [ ] Security Review:
  * [ ] Verify TLS/SSL connection requirements (if applicable).
  * [ ] Ensure database user has least privilege.

## 10. Recent Architectural Improvements

### 10.1 SQLAlchemy Model Base Class Consolidation

We identified and resolved a critical architectural issue with multiple SQLAlchemy base class definitions causing registry conflicts. The solution includes:

1. **Canonical Base Class**: Established `app/infrastructure/database/base_class.py` as the single source of truth for all model definitions.
2. **Centralized Metadata**: Ensured all models share a single `MetaData` instance for consistent schema management.
3. **Model Registration**: Implemented a decorator-based registration system to track and validate all models.
4. **Common Mixins**: Standardized timestamp and audit fields through reusable mixins.

### 10.2 Relationship Definition Improvements

Fixed bidirectional relationship issues between key models:

1. **User-Provider Relationship**: Simplified the relationship definitions between User and Provider models by:
   * Removing redundant `primaryjoin` and `foreign_keys` parameters
   * Using `back_populates` consistently on both sides
   * Eliminating circular dependencies caused by misuse of `viewonly=True`

2. **Cross-Database Type Compatibility**: Replaced PostgreSQL-specific types with cross-database compatible alternatives:
   * Used `JSONEncodedDict` instead of `JSONB` in the `AuditLog` model
   * Standardized on the custom `GUID` type for all UUID fields

These improvements have resolved mapping errors and ensured consistent behavior across development and production environments.