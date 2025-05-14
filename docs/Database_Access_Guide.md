# Database Access Guide

## Overview

This document outlines the implementation of database access patterns in the Clarity AI Backend. Following clean architecture principles, all database operations are encapsulated in the infrastructure layer, accessed through repository interfaces defined in the core layer, and coordinated through dependency injection.

## Core Principles

1. **Separation of Concerns**: Database access is isolated in the infrastructure layer
2. **Repository Pattern**: Domain entities are persisted through repository interfaces
3. **Dependency Inversion**: Higher layers depend on abstractions, not concrete implementations
4. **Unit of Work**: Transactions span multiple repositories when needed
5. **HIPAA Compliance**: Secure, audited, and controlled access to PHI

## SQLAlchemy Configuration

### Connection Management

```python
# app/infrastructure/persistence/database.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from contextlib import asynccontextmanager
from app.core.config import settings

# Create engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.SQL_ECHO,
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW
)

# Session factory
AsyncSessionFactory = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

@asynccontextmanager
async def get_db_session():
    """Provide an async session with automatic cleanup."""
    session = AsyncSessionFactory()
    try:
        yield session
    finally:
        await session.close()
```

### Application Factory Integration

```python
# app/app_factory.py
from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.infrastructure.persistence.database import engine, AsyncSessionFactory
from app.presentation.api.dependencies.database import get_db_session

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup
    yield
    # Cleanup
    await engine.dispose()

def create_app():
    app = FastAPI(lifespan=lifespan)
    # ... other configurations
    return app
```

### Dependency Injection

```python
# app/presentation/api/dependencies/database.py
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.infrastructure.persistence.database import get_db_session

async def get_db(session: AsyncSession = Depends(get_db_session)):
    """Dependency for database session."""
    return session
```

## Repository Pattern Implementation

### Repository Interface

```python
# app/core/interfaces/repositories/patient_repository_interface.py
from abc import ABC, abstractmethod
from typing import List, Optional
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId

class IPatientRepository(ABC):
    """Interface for patient repository operations."""
    
    @abstractmethod
    async def get_by_id(self, patient_id: PatientId) -> Optional[Patient]:
        """Get patient by ID."""
        pass
    
    @abstractmethod
    async def get_by_mrn(self, mrn: str) -> Optional[Patient]:
        """Get patient by medical record number."""
        pass
    
    @abstractmethod
    async def create(self, patient: Patient) -> Patient:
        """Create a new patient."""
        pass
    
    @abstractmethod
    async def update(self, patient: Patient) -> Patient:
        """Update an existing patient."""
        pass
    
    @abstractmethod
    async def delete(self, patient_id: PatientId) -> bool:
        """Delete a patient."""
        pass
    
    @abstractmethod
    async def search(self, criteria: dict, skip: int = 0, limit: int = 100) -> List[Patient]:
        """Search for patients matching criteria."""
        pass
```

### SQL Alchemy Models

```python
# app/infrastructure/persistence/models/patient.py
from sqlalchemy import Column, String, Date, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.infrastructure.persistence.models.base import Base
import uuid

class PatientModel(Base):
    """SQLAlchemy model for patients."""
    
    __tablename__ = "patients"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    medical_record_number = Column(String(50), unique=True, nullable=False, index=True)
    date_of_birth = Column(Date, nullable=False)
    notes = Column(Text, nullable=True)
    
    # Relationships
    biometric_readings = relationship(
        "BiometricReadingModel",
        back_populates="patient",
        cascade="all, delete-orphan"
    )
```

### SQLAlchemy Repository Implementation

```python
# app/infrastructure/persistence/repositories/sqlalchemy_patient_repository.py
from typing import List, Optional, Dict, Any
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.core.interfaces.repositories import IPatientRepository
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId
from app.infrastructure.persistence.models import PatientModel
from app.infrastructure.persistence.mappers import PatientMapper

class SQLAlchemyPatientRepository(IPatientRepository):
    """SQLAlchemy implementation of patient repository."""
    
    def __init__(self, session: AsyncSession):
        self._session = session
        self._mapper = PatientMapper()
    
    async def get_by_id(self, patient_id: PatientId) -> Optional[Patient]:
        """
        Get patient by ID.
        
        Args:
            patient_id: Unique identifier for the patient
            
        Returns:
            Patient entity if found, None otherwise
        """
        query = (
            select(PatientModel)
            .options(selectinload(PatientModel.biometric_readings))
            .where(PatientModel.id == str(patient_id))
        )
        
        result = await self._session.execute(query)
        model = result.scalars().first()
        
        if not model:
            return None
            
        return self._mapper.to_entity(model)
    
    async def create(self, patient: Patient) -> Patient:
        """
        Create a new patient record.
        
        Args:
            patient: Patient entity to persist
            
        Returns:
            The created patient with database-generated values
        """
        # Convert domain entity to database model
        model = self._mapper.to_model(patient)
        
        # Add to session and flush to generate ID
        self._session.add(model)
        await self._session.flush()
        
        # Convert back to domain entity with generated ID
        return self._mapper.to_entity(model)
```

### Dependency Registration

```python
# app/presentation/api/dependencies/repositories.py
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.interfaces.repositories import IPatientRepository
from app.infrastructure.persistence.repositories import SQLAlchemyPatientRepository
from app.presentation.api.dependencies.database import get_db

def get_patient_repository(
    session: AsyncSession = Depends(get_db)
) -> IPatientRepository:
    """Dependency provider for patient repository."""
    return SQLAlchemyPatientRepository(session)
```

## Unit of Work Pattern

Used to manage database transactions across multiple repositories:

```python
# app/core/interfaces/unit_of_work.py
from abc import ABC, abstractmethod

class IUnitOfWork(ABC):
    """Interface for unit of work pattern."""
    
    @abstractmethod
    async def __aenter__(self):
        """Begin a new transaction."""
        pass
    
    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """End the transaction (with rollback if exception)."""
        pass
    
    @abstractmethod
    async def commit(self):
        """Commit the transaction."""
        pass
    
    @abstractmethod
    async def rollback(self):
        """Rollback the transaction."""
        pass
```

The SQLAlchemy implementation:

```python
# app/infrastructure/persistence/unit_of_work.py
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.interfaces.unit_of_work import IUnitOfWork

class SQLAlchemyUnitOfWork(IUnitOfWork):
    """SQLAlchemy implementation of unit of work."""
    
    def __init__(self, session: AsyncSession):
        self._session = session
        self._transaction = None
    
    async def __aenter__(self):
        """Begin a new transaction."""
        self._transaction = await self._session.begin_nested()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """End the transaction (with rollback if exception)."""
        if exc_type:
            await self.rollback()
        else:
            await self.commit()
    
    async def commit(self):
        """Commit the transaction."""
        if self._transaction:
            await self._transaction.commit()
            self._transaction = None
    
    async def rollback(self):
        """Rollback the transaction."""
        if self._transaction:
            await self._transaction.rollback()
            self._transaction = None
```

## Entity-Model Mapping

Bidirectional mapping between domain entities and database models:

```python
# app/infrastructure/persistence/mappers/patient_mapper.py
from typing import Optional
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId
from app.infrastructure.persistence.models import PatientModel
from datetime import datetime

class PatientMapper:
    """Maps between Patient entity and PatientModel."""
    
    def to_entity(self, model: PatientModel) -> Patient:
        """
        Convert database model to domain entity.
        
        Args:
            model: Database model
            
        Returns:
            Domain entity
        """
        return Patient(
            id=PatientId(model.id),
            name=model.name,
            medical_record_number=model.medical_record_number,
            date_of_birth=model.date_of_birth,
            notes=model.notes
        )
    
    def to_model(self, entity: Patient) -> PatientModel:
        """
        Convert domain entity to database model.
        
        Args:
            entity: Domain entity
            
        Returns:
            Database model
        """
        return PatientModel(
            id=str(entity.id) if entity.id else None,
            name=entity.name,
            medical_record_number=entity.medical_record_number,
            date_of_birth=entity.date_of_birth,
            notes=entity.notes
        )
```

## Migrations with Alembic

```python
# alembic/env.py
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
from app.infrastructure.persistence.models.base import Base
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import all models to ensure they're registered with Base
from app.infrastructure.persistence.models import *

# Alembic configuration
config = context.config

# Set SQLAlchemy URL if not set in alembic.ini
if not config.get_main_option("sqlalchemy.url"):
    from app.core.config import settings
    config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
```

## Query Building Patterns

For complex queries, use builder pattern instead of raw SQL:

```python
# app/infrastructure/persistence/query_builders/patient_query_builder.py
from sqlalchemy import select, func, and_, or_
from sqlalchemy.sql.expression import Select
from app.infrastructure.persistence.models import PatientModel, BiometricReadingModel

class PatientQueryBuilder:
    """Builder for complex patient queries."""
    
    def __init__(self):
        self._query = select(PatientModel)
        self._where_clauses = []
    
    def with_biometric_readings(self) -> 'PatientQueryBuilder':
        """Include biometric readings in the query."""
        from sqlalchemy.orm import selectinload
        self._query = self._query.options(
            selectinload(PatientModel.biometric_readings)
        )
        return self
    
    def with_name_like(self, name_fragment: str) -> 'PatientQueryBuilder':
        """Filter patients by name similarity."""
        self._where_clauses.append(
            PatientModel.name.ilike(f"%{name_fragment}%")
        )
        return self
    
    def with_age_range(self, min_age: int, max_age: int) -> 'PatientQueryBuilder':
        """Filter patients by age range."""
        from datetime import date, timedelta
        today = date.today()
        min_date = date(today.year - max_age - 1, today.month, today.day)
        max_date = date(today.year - min_age, today.month, today.day)
        
        self._where_clauses.append(
            and_(
                PatientModel.date_of_birth >= min_date,
                PatientModel.date_of_birth <= max_date
            )
        )
        return self
    
    def build(self) -> Select:
        """Build the final query."""
        if self._where_clauses:
            self._query = self._query.where(and_(*self._where_clauses))
        return self._query
```

## HIPAA-Compliant Data Access

### Patient Data Access Control

```python
# app/infrastructure/persistence/repositories/sqlalchemy_patient_repository.py
from app.core.interfaces.security import IAccessControlService
from app.core.domain.errors import UnauthorizedAccessError

class SQLAlchemyPatientRepository(IPatientRepository):
    def __init__(
        self,
        session: AsyncSession,
        access_control: IAccessControlService,
        current_user_id: str
    ):
        self._session = session
        self._mapper = PatientMapper()
        self._access_control = access_control
        self._current_user_id = current_user_id
    
    async def get_by_id(self, patient_id: PatientId) -> Optional[Patient]:
        # Get patient from database
        query = select(PatientModel).where(PatientModel.id == str(patient_id))
        result = await self._session.execute(query)
        model = result.scalars().first()
        
        if not model:
            return None
        
        # Check if current user has access to this patient
        has_access = await self._access_control.can_access_patient(
            user_id=self._current_user_id,
            patient_id=str(patient_id)
        )
        
        if not has_access:
            raise UnauthorizedAccessError(
                f"User {self._current_user_id} does not have access to patient {patient_id}"
            )
        
        return self._mapper.to_entity(model)
```

### Audit Logging for Database Operations

```python
# app/infrastructure/persistence/audit_logging.py
from sqlalchemy import event
from sqlalchemy.orm import Session
from app.infrastructure.persistence.models import PatientModel, BiometricReadingModel
from app.infrastructure.logging import audit_logger
from app.core.security.context import get_current_user_id
import json

def setup_audit_listeners():
    """Configure SQLAlchemy event listeners for audit logging."""
    
    @event.listens_for(PatientModel, 'after_update')
    def log_patient_update(mapper, connection, target):
        """Log updates to patient records."""
        user_id = get_current_user_id()
        audit_logger.log_phi_access(
            user_id=user_id,
            action="update",
            resource_type="Patient",
            resource_id=target.id
        )
    
    @event.listens_for(PatientModel, 'after_delete')
    def log_patient_delete(mapper, connection, target):
        """Log deletion of patient records."""
        user_id = get_current_user_id()
        audit_logger.log_phi_access(
            user_id=user_id,
            action="delete",
            resource_type="Patient",
            resource_id=target.id
        )
```

## Database Encryption for PHI

```python
# app/infrastructure/persistence/encryption.py
from sqlalchemy import event, Column
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.types import TypeDecorator, String
from app.core.security.encryption import encrypt, decrypt

class EncryptedString(TypeDecorator):
    """Custom SQLAlchemy type for encrypted string data."""
    
    impl = String
    
    def process_bind_param(self, value, dialect):
        """Encrypt data before storage."""
        if value is not None:
            return encrypt(value)
        return value
    
    def process_result_value(self, value, dialect):
        """Decrypt data after retrieval."""
        if value is not None:
            return decrypt(value)
        return value

# Usage in models
class PatientModel(Base):
    # ...
    medical_record_number = Column(EncryptedString(100), unique=True, nullable=False)
    ssn = Column(EncryptedString(11), nullable=True)
```

## Connection Pooling and Performance

Configuration settings for optimal database performance:

```python
# app/core/config.py
from pydantic import Field, AnyUrl
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database settings
    DATABASE_URL: AnyUrl = Field(..., env="DATABASE_URL")
    DB_POOL_SIZE: int = Field(5, env="DB_POOL_SIZE")
    DB_MAX_OVERFLOW: int = Field(10, env="DB_MAX_OVERFLOW")
    DB_POOL_TIMEOUT: int = Field(30, env="DB_POOL_TIMEOUT")
    DB_POOL_RECYCLE: int = Field(1800, env="DB_POOL_RECYCLE")  # 30 minutes
    SQL_ECHO: bool = Field(False, env="SQL_ECHO")
```

## Error Handling

Translating database errors to domain errors:

```python
# app/infrastructure/persistence/repositories/sqlalchemy_base_repository.py
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from app.core.domain.errors import (
    DatabaseError,
    UniqueConstraintError,
    ForeignKeyError
)

class SQLAlchemyBaseRepository:
    """Base class for SQLAlchemy repositories with common error handling."""
    
    async def _handle_db_operation(self, operation):
        """
        Execute database operation with error handling.
        
        Args:
            operation: Async callable that performs database operations
            
        Returns:
            Result of the operation
            
        Raises:
            Domain-specific errors translated from SQLAlchemy exceptions
        """
        try:
            return await operation()
        except IntegrityError as e:
            # Check error details to determine specific constraint violation
            error_msg = str(e)
            if "unique constraint" in error_msg.lower():
                raise UniqueConstraintError(
                    "A record with this identifier already exists"
                ) from e
            elif "foreign key constraint" in error_msg.lower():
                raise ForeignKeyError(
                    "Referenced record does not exist"
                ) from e
            else:
                raise DatabaseError(str(e)) from e
        except SQLAlchemyError as e:
            raise DatabaseError(str(e)) from e
```

## Testing

### Test Database Configuration

```python
# app/tests/conftest.py
import pytest
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.infrastructure.persistence.models.base import Base

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def test_engine():
    """Create test engine with in-memory SQLite."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()

@pytest.fixture
async def test_session(test_engine):
    """Create test session with rollback after each test."""
    async_session = sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False
    )
    
    async with async_session() as session:
        async with session.begin():
            yield session
            await session.rollback()
```

### Repository Testing

```python
# app/tests/integration/repositories/test_patient_repository.py
import pytest
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId
from app.infrastructure.persistence.repositories import SQLAlchemyPatientRepository

@pytest.fixture
def patient_data():
    """Test patient data."""
    return {
        "name": "Test Patient",
        "medical_record_number": "MRN123456",
        "date_of_birth": "1990-01-01"
    }

@pytest.fixture
def patient_entity(patient_data):
    """Create test patient entity."""
    return Patient(
        id=None,  # Will be generated on create
        **patient_data
    )

@pytest.mark.asyncio
async def test_create_patient(test_session, patient_entity):
    # Arrange
    repository = SQLAlchemyPatientRepository(test_session)
    
    # Act
    created_patient = await repository.create(patient_entity)
    
    # Assert
    assert created_patient is not None
    assert created_patient.id is not None
    assert created_patient.name == patient_entity.name
    assert created_patient.medical_record_number == patient_entity.medical_record_number
```

## Current Implementation Status

### Strengths

- Clean separation between domain entities and ORM models
- Repository pattern consistently applied for all database access
- Unit of Work pattern for transaction management
- HIPAA-compliant audit logging of all PHI access

### Architectural Gaps

- Some repositories access models directly instead of using mappers
- Inconsistent error handling across repositories
- Query builders not yet implemented for all entities
- Encryption needs to be applied to all PHI fields

### Performance Considerations

- Connection pooling and timeout settings need tuning based on load testing
- Consider implementing caching for frequently accessed data
- Database indexes need optimization for common query patterns
- Long-running transactions need monitoring and possible timeout

By following these patterns, the Clarity AI Backend maintains a clean, maintainable database access layer that properly encapsulates infrastructure concerns while enforcing security, compliance, and architectural boundaries.
