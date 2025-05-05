# Clarity AI Backend - Database Documentation

## 1. Overview

The database is a critical component of the Clarity AI Backend, responsible for persistent storage of all core application data, including user information, patient data (handled with extreme care according to HIPAA), digital twin configurations, interaction logs, and potentially other domain-specific entities. This document outlines the technology, configuration, schema management, and considerations for both production and testing environments.

## 2. Technology Stack

* Production Database: PostgreSQL (Assumed standard, requires confirmation based on `ASYNC_DATABASE_URI`)
* Testing Database: SQLite (In-memory)
* ORM: SQLAlchemy (Asynchronous using `asyncio` extension)
* Migrations: Alembic (Assumed standard for SQLAlchemy schema migrations)
* Driver: `asyncpg` (for PostgreSQL), `aiosqlite` (for SQLite)

## 3. Production Configuration

* Connection URI: Defined by the `ASYNC_DATABASE_URI` environment variable, loaded via `app.core.config.Settings`.
* Initialization: The SQLAlchemy `AsyncEngine` and session factory (`sessionmaker`) are created during application startup within the `lifespan` context manager in `app/app_factory.py`.
* State Management: The engine and session factory are stored in the `FastAPI` application state (`app.state.db_engine`, `app.state.db_session_factory`) for accessibility.
* Session Management:
  * A request-scoped `AsyncSession` is provided via the `get_async_session` dependency (`app.infrastructure.database.session.get_async_session`).
  * This dependency likely retrieves the session factory from `request.app.state` and yields a session, ensuring proper session handling per request.
  * Error handling within the dependency ensures sessions are closed/rolled back appropriately.

## 4. Testing Configuration (`app/tests/conftest.py`)

* Database: Uses an in-memory SQLite database (`sqlite+aiosqlite:///:memory:`) configured via `test_settings` overriding the main settings.
* Engine (`test_db_engine` fixture):
  * Session-scoped `AsyncEngine`.
  * Uses `StaticPool` suitable for SQLite.
  * Handles table creation (`Base.metadata.create_all`) before tests run and table dropping (`Base.metadata.drop_all`) after tests complete within the session scope.
* Session (`db_session` fixture):
  * Function-scoped `AsyncSession`.
  * Begins a transaction at the start of each test.
  * Yields the session to the test function.
  * Rolls back the transaction upon test completion, ensuring test isolation.
* Dependency Override (`initialized_app` fixture):
  * Creates the FastAPI application instance for testing.
  * Crucially, overrides the application's `get_async_session` dependency.
  * The override provides the specific, transaction-managed `AsyncSession` instance yielded by the `db_session` fixture, ensuring tests operate within the controlled transaction.

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
* Base Model: All models should inherit from the declarative base defined in `app/infrastructure/database/base_class.py` (`Base`).
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

* [x] Models: Define all required SQLAlchemy models in `app/infrastructure/persistence/sqlalchemy/models/`, inheriting from `Base`.
* [x] Relationships: Correctly define relationships (one-to-one, one-to-many, many-to-many) between models (core models addressed).
* [ ] Constraints: Add necessary `UniqueConstraint`, `CheckConstraint`, `ForeignKeyConstraint`, `Index` definitions within models.
* [x] Configuration: Set up `ASYNC_DATABASE_URI` environment variable for development, staging, and production environments.
* [ ] Alembic Setup:
  * [ ] Initialize Alembic (`alembic init alembic`).
  * [ ] Configure `alembic.ini` (set `sqlalchemy.url`).
  * [ ] Configure `alembic/env.py` (target `Base.metadata`, import models).
* [ ] Initial Migration:
  * [ ] Generate initial schema migration (`alembic revision --autogenerate -m "Initial schema setup"`).
  * [ ] Apply the migration (`alembic upgrade head`).
* [ ] Test Verification: Ensure all tests pass, confirming the `conftest.py` setup correctly manages test database sessions and isolation (In Progress - Fixing test errors).
* [ ] Indexing: Review critical query patterns and add necessary indexes to models.
* [ ] Security Review:
  * [x] Confirm no hardcoded credentials.
  * [ ] Verify TLS/SSL connection requirements (if applicable).
  * [ ] Ensure database user has least privilege.
* [ ] Documentation: Keep this document updated as the database schema or configuration evolves (In Progress).