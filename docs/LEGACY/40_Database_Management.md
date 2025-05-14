# 40. Database Management & ORM Guide

This document details the platform's approach to database interactions, including the Object-Relational Mapper (ORM), session management, the Repository pattern, data modeling, migrations, and testing.

---

## 1. Overview

The backend utilizes a relational database (e.g., PostgreSQL) managed via SQLAlchemy as the ORM. Data access is structured primarily through the Repository pattern to decouple application logic from data persistence concerns.

## 2. ORM Configuration (SQLAlchemy)

- **Core ORM**: SQLAlchemy is used for mapping Python objects to database tables.
- **Base Model**: A declarative base (`database.base_class.Base`) is likely used for defining ORM models (e.g., `database.models.PatientModel`). All database models should inherit from this base.
- **Engine & Connection**: The database engine is configured based on environment variables (see `core.config`). Specific connection details (URL, pool size) are managed centrally.

## 3. Session Management

- **Async Sessions**: Given the use of FastAPI and async capabilities, `AsyncSession` from SQLAlchemy is the standard for database sessions.
- **Dependency Injection (FastAPI)**: Database sessions are typically managed per request using FastAPI's dependency injection system. A dependency (e.g., defined in `app.dependencies` or similar) likely provides an `AsyncSession` to API route handlers and, subsequently, to application services and repositories.
- **Session Scope**: Sessions obtained via dependency injection are scoped to a single request. The dependency injector handles opening and closing/rolling back the session and associated transaction.
- **Manual Session Handling**: Avoid manual session creation/management within application or domain logic; rely on the injected session.

## 4. Repository Pattern

- **Purpose**: To abstract the details of data access and persistence. Application services interact with repositories, not directly with the ORM or database sessions for complex queries/operations.
- **Location**: Repository interfaces are ideally defined within the `domain` or `application` layer, while their concrete implementations reside in the `infrastructure` layer (e.g., `/backend/app/infrastructure/repositories/`).
- **Implementation**: Repositories receive a database session (e.g., `AsyncSession`) via dependency injection in their constructor. They use this session to perform CRUD operations and other data queries using SQLAlchemy.
- **Example**:
  ```python
  # --- Interface (e.g., in application layer) ---
  class PatientRepository(Protocol):
      async def get_by_id(self, patient_id: UUID) -> Optional[Patient]: ...
      async def create(self, patient_data: PatientCreate) -> Patient: ...
      # ... other methods

  # --- Implementation (in infrastructure layer) ---
  from sqlalchemy.ext.asyncio import AsyncSession
  from sqlalchemy.future import select
  from .models import PatientModel # Assuming infrastructure has access to models

  class SQLPatientRepository: # Implements PatientRepository protocol
      def __init__(self, db: AsyncSession):
          self._db = db

      async def get_by_id(self, patient_id: UUID) -> Optional[Patient]:
          result = await self._db.execute(
              select(PatientModel).where(PatientModel.id == patient_id)
          )
          db_patient = result.scalars().first()
          # Map db_patient (PatientModel) to domain Patient object if necessary
          return Patient.from_orm(db_patient) if db_patient else None

      async def create(self, patient_data: PatientCreate) -> Patient:
          db_patient = PatientModel(**patient_data.dict()) # Assuming Pydantic model
          self._db.add(db_patient)
          await self._db.flush()
          await self._db.refresh(db_patient)
          # Map db_patient to domain Patient object
          return Patient.from_orm(db_patient)
      # ...
  ```

## 5. Data Models & Persistence Structure

- **Core DB Setup Location**: Core SQLAlchemy configuration (session management, declarative base) is located in `/backend/app/infrastructure/database/` (e.g., `session.py`, `base_class.py`).
- **Persistence Logic Location**: Concrete persistence implementations, including specific ORM models (potentially in `/backend/app/infrastructure/persistence/sqlalchemy/`) and repository implementations (`/backend/app/infrastructure/persistence/repositories/`), reside within the `/backend/app/infrastructure/persistence/` directory. This separation keeps core setup distinct from specific table models and query logic.
- **Definition**: Models inherit from the declarative base (`infrastructure.database.base_class.Base`) and use SQLAlchemy column types and relationships.
- **Relationship to Domain**: ORM models represent the database schema. They might differ slightly from pure domain models. Mappings between ORM models and domain entities/DTOs might be necessary, often handled within repositories or dedicated mapping functions.

## 6. Database Migrations

- **Tooling**: [Specify Tool, e.g., Alembic - Needs Verification] is likely used for managing database schema migrations.
- **Location**: Migration scripts are typically stored in a dedicated directory (e.g., `/backend/alembic/versions/`).
- **Process**: Migrations should be generated automatically based on changes to SQLAlchemy models and reviewed before application. CI/CD pipelines should handle applying migrations to different environments. *(Verify if Alembic or similar is configured)*.

## 7. Testing Database Interactions

Refer to `80_Testing_Guide.md` for general testing philosophy. Specific strategies for database code include:

- **Integration Tests**:
    - **Preferred Method**: Use dedicated test databases (e.g., temporary PostgreSQL databases, potentially spun up via Docker).
    - **Fixtures**: Pytest fixtures (e.g., in `conftest.py`) should manage the creation, setup (applying migrations), and teardown of test databases and sessions.
    - **Scope**: Test repository implementations directly against the test database to ensure SQL queries and ORM mappings are correct. Also test application services or API endpoints that rely on these repositories.
- **Unit Tests (Mocking)**:
    - **Use Case**: For testing application service logic without the overhead of a database connection, repositories can be mocked.
    - **Approach**: Inject mock repository objects that conform to the repository interface but return predefined data.
    - **Caution**: Over-reliance on mocking can lead to tests passing even if underlying database queries are broken. Ensure critical paths are covered by integration tests.

---

This guide provides the foundational strategy for database management. Ensure code adheres to these patterns for consistency and maintainability.

Last Updated: 2025-04-20
