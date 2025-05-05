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

## 5. Schema Management (PRD Requirement)

* Definition: Database schema (tables, columns, constraints, relationships) is defined using SQLAlchemy models located primarily within `app/core/domain/entities/`.
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

* Models: Define all required SQLAlchemy models in `app/core/domain/entities/`, inheriting from `Base`.
* Relationships: Correctly define relationships (one-to-one, one-to-many, many-to-many) between models.
* Constraints: Add necessary `UniqueConstraint`, `CheckConstraint`, `ForeignKeyConstraint`, `Index` definitions within models.
* Configuration: Set up `ASYNC_DATABASE_URI` environment variable for development, staging, and production environments.
* Alembic Setup:
  * Initialize Alembic (`alembic init alembic`).
  * Configure `alembic.ini` (set `sqlalchemy.url`).
  * Configure `alembic/env.py` (target `Base.metadata`, import models).
* Initial Migration:
  * Generate initial schema migration (`alembic revision --autogenerate -m "Initial schema setup"`).
  * Apply the migration (`alembic upgrade head`).
* Test Verification: Ensure all tests pass, confirming the `conftest.py` setup correctly manages test database sessions and isolation.
* Indexing: Review critical query patterns and add necessary indexes to models.
* Security Review:
  * Confirm no hardcoded credentials.
  * Verify TLS/SSL connection requirements (if applicable).
  * Ensure database user has least privilege.
* Documentation: Keep this document updated as the database schema or configuration evolves.