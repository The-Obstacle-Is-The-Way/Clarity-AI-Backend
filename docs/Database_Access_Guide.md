# Database Access Guide

## Overview

This document outlines the database access patterns in the Clarity AI Backend, with a focus on HIPAA compliance and clean architecture principles. The system uses a repository pattern to abstract database operations, providing a secure and consistent approach to handling Protected Health Information (PHI) while maintaining architectural boundaries.

## HIPAA-Compliant Database Access

### Core HIPAA Requirements for Data Storage

The database access layer implements these HIPAA Security Rule requirements:

1. **Access Controls** (§164.312(a)(1)): Granular access permissions to PHI
2. **Audit Controls** (§164.312(b)): Comprehensive logging of all PHI access
3. **Integrity Controls** (§164.312(c)(1)): Data validation and corruption prevention
4. **Person or Entity Authentication** (§164.312(d)): Verified identity for database access
5. **Transmission Security** (§164.312(e)(1)): Encryption of data in transit
6. **Encryption** (§164.312(a)(2)(iv)): Field-level encryption of PHI at rest

### PHI Handling in Repositories

All repositories that handle PHI implement these security measures:

1. **Field-Level Encryption**: Sensitive fields are encrypted before storage
2. **Access Audit Logging**: Every PHI access is logged with user context
3. **Authorization Checks**: Repositories verify access permissions
4. **Minimal PHI Exposure**: Only necessary PHI fields are retrieved
5. **Secure Error Handling**: Errors don't expose PHI details

## Repository Pattern Implementation

### Repository Interface Definition

Repository interfaces are defined in the domain layer, following the Dependency Inversion Principle:

```python
# app/domain/interfaces/repositories/patient_repository_interface.py
from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID
from app.domain.entities.patient import Patient
from app.domain.value_objects.user_id import UserId

class IPatientRepository(ABC):
    """
    Repository interface for patient data access.
    
    Implements HIPAA-compliant data access patterns for patient PHI.
    """
    
    @abstractmethod
    async def get_by_id(
        self, 
        patient_id: UUID, 
        requesting_user_id: UserId
    ) -> Optional[Patient]:
        """
        Get a patient by ID with proper access logging.
        
        Args:
            patient_id: The patient's unique identifier
            requesting_user_id: ID of the user requesting access (for audit)
            
        Returns:
            Patient entity if found and accessible, None otherwise
        """
        pass
    
    @abstractmethod
    async def create(
        self, 
        patient: Patient,
        created_by: UserId
    ) -> Patient:
        """
        Create a new patient record with audit logging.
        
        Args:
            patient: Patient entity to persist
            created_by: ID of the user creating the record
            
        Returns:
            Created patient with database-generated fields
        """
        pass
    
    @abstractmethod
    async def update(
        self, 
        patient: Patient,
        updated_by: UserId
    ) -> Patient:
        """
        Update a patient record with audit logging.
        
        Args:
            patient: Updated patient entity
            updated_by: ID of the user updating the record
            
        Returns:
            Updated patient entity
        """
        pass
    
    @abstractmethod
    async def delete(
        self, 
        patient_id: UUID,
        deleted_by: UserId
    ) -> bool:
        """
        Delete a patient record with audit logging.
        
        Args:
            patient_id: ID of the patient to delete
            deleted_by: ID of the user performing deletion
            
        Returns:
            True if successfully deleted
        """
        pass
    
    @abstractmethod
    async def search(
        self, 
        criteria: dict,
        requesting_user_id: UserId,
        skip: int = 0, 
        limit: int = 100
    ) -> List[Patient]:
        """
        Search for patients matching criteria with audit logging.
        
        Args:
            criteria: Search criteria
            requesting_user_id: ID of the user performing search
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of matching patient entities
        """
        pass
```

### HIPAA-Compliant Database Models

SQLAlchemy models are designed with field-level encryption for PHI:

```python
# app/infrastructure/persistence/models/patient_model.py
from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.infrastructure.persistence.models.base import Base
from datetime import datetime
import uuid

class PatientModel(Base):
    """SQLAlchemy model for patient data with PHI encryption."""
    
    __tablename__ = "patients"
    
    # Non-PHI fields (not encrypted)
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    active = Column(Boolean, nullable=False, default=True)
    
    # PHI fields (stored encrypted)
    _first_name = Column("first_name_encrypted", String, nullable=False)
    _last_name = Column("last_name_encrypted", String, nullable=False)
    _date_of_birth = Column("dob_encrypted", String, nullable=False)
    _ssn = Column("ssn_encrypted", String, nullable=True)
    _email = Column("email_encrypted", String, nullable=True)
    _phone = Column("phone_encrypted", String, nullable=True)
    _address = Column("address_encrypted", String, nullable=True)
    
    # Relationships
    medical_records = relationship("MedicalRecordModel", back_populates="patient", cascade="all, delete-orphan")
    medications = relationship("MedicationModel", back_populates="patient", cascade="all, delete-orphan")
    biometric_readings = relationship("BiometricReadingModel", back_populates="patient", cascade="all, delete-orphan")
```

### Encrypted PHI Value Object

The system uses a specialized value object for handling encrypted PHI:

```python
# app/domain/value_objects/encrypted_phi.py
from app.core.interfaces.services.encryption_service_interface import IEncryptionService
from app.infrastructure.di.container import get_container

class EncryptedPHI:
    """
    Value object for handling encrypted PHI.
    
    This class ensures PHI is always encrypted at rest and
    only decrypted when explicitly requested by authorized code.
    """
    
    def __init__(
        self,
        plaintext: str = None,
        ciphertext: str = None,
        encryption_service: IEncryptionService = None
    ):
        """
        Initialize encrypted PHI value object.
        
        Args:
            plaintext: Raw PHI data to encrypt
            ciphertext: Already encrypted PHI data
            encryption_service: Service for encryption/decryption
        """
        if encryption_service is None:
            container = get_container()
            encryption_service = container.get(IEncryptionService)
            
        self._encryption_service = encryption_service
        
        if plaintext is not None:
            self.ciphertext = self._encryption_service.encrypt(plaintext)
        elif ciphertext is not None:
            self.ciphertext = ciphertext
        else:
            raise ValueError("Either plaintext or ciphertext must be provided")
    
    def get_plaintext(self) -> str:
        """
        Decrypt and return the PHI.
        
        This method should only be called when necessary and
        with proper audit logging in place.
        
        Returns:
            Decrypted PHI value
        """
        return self._encryption_service.decrypt(self.ciphertext)
    
    def __str__(self) -> str:
        """Return a string representation that doesn't expose PHI."""
        return "[ENCRYPTED PHI]"
    
    def __repr__(self) -> str:
        """Return a debug representation that doesn't expose PHI."""
        return f"EncryptedPHI(ciphertext='{self.ciphertext[:5]}...{self.ciphertext[-5:]}')"
```

### HIPAA-Compliant Repository Implementation

The SQLAlchemy repository implementation ensures PHI is properly protected:

```python
# app/infrastructure/persistence/repositories/sqlalchemy_patient_repository.py
from typing import List, Optional, Dict, Any
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.interfaces.repositories.patient_repository_interface import IPatientRepository
from app.domain.entities.patient import Patient
from app.domain.value_objects.user_id import UserId
from app.domain.value_objects.encrypted_phi import EncryptedPHI
from app.infrastructure.persistence.models.patient_model import PatientModel
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.core.interfaces.services.encryption_service_interface import IEncryptionService
from uuid import UUID

class SQLAlchemyPatientRepository(IPatientRepository):
    """
    SQLAlchemy implementation of patient repository with HIPAA compliance.
    
    This repository handles:
    - Field-level PHI encryption
    - Access audit logging
    - Permission verification
    - Secure error handling
    """
    
    def __init__(
        self, 
        session: AsyncSession,
        audit_logger: IAuditLogger,
        encryption_service: IEncryptionService
    ):
        """Initialize repository with required dependencies."""
        self._session = session
        self._audit_logger = audit_logger
        self._encryption_service = encryption_service
    
    async def get_by_id(
        self, 
        patient_id: UUID, 
        requesting_user_id: UserId
    ) -> Optional[Patient]:
        """
        Get patient by ID with HIPAA-compliant audit logging.
        
        Args:
            patient_id: Patient's unique identifier
            requesting_user_id: ID of the user requesting access
            
        Returns:
            Patient entity if found, None otherwise
        """
        try:
            # Log PHI access before retrieval
            await self._audit_logger.log_phi_access(
                user_id=str(requesting_user_id),
                resource_type="patient",
                resource_id=str(patient_id),
                action="view"
            )
            
            # Retrieve patient model
            result = await self._session.execute(
                select(PatientModel).where(PatientModel.id == patient_id)
            )
            
            patient_model = result.scalars().first()
            
            if not patient_model:
                return None
                
            # Convert database model to domain entity
            return self._model_to_entity(patient_model)
            
        except Exception as e:
            # Log error without exposing PHI
            await self._audit_logger.log_security_event(
                event_type="database_error",
                user_id=str(requesting_user_id),
                description=f"Error retrieving patient data: {type(e).__name__}",
                severity="ERROR"
            )
            # Re-raise as domain exception without PHI
            raise DatabaseAccessException(
                message="Error retrieving patient data",
                original_exception=e
            )
    
    async def create(
        self, 
        patient: Patient,
        created_by: UserId
    ) -> Patient:
        """
        Create patient with HIPAA-compliant audit logging.
        
        Args:
            patient: Patient entity to create
            created_by: ID of the user creating the record
            
        Returns:
            Created patient with database-generated values
        """
        try:
            # Convert domain entity to database model with encryption
            patient_model = self._entity_to_model(patient)
            
            # Add to database
            self._session.add(patient_model)
            await self._session.flush()
            
            # Log PHI access for creation
            await self._audit_logger.log_phi_access(
                user_id=str(created_by),
                resource_type="patient",
                resource_id=str(patient_model.id),
                action="create"
            )
            
            # Return domain entity with database-generated values
            return self._model_to_entity(patient_model)
            
        except Exception as e:
            # Log error without exposing PHI
            await self._audit_logger.log_security_event(
                event_type="database_error",
                user_id=str(created_by),
                description=f"Error creating patient record: {type(e).__name__}",
                severity="ERROR"
            )
            # Re-raise as domain exception without PHI
            raise DatabaseAccessException(
                message="Error creating patient record",
                original_exception=e
            )
    
    def _entity_to_model(self, patient: Patient) -> PatientModel:
        """
        Convert domain entity to database model with PHI encryption.
        
        Args:
            patient: Domain entity
            
        Returns:
            SQLAlchemy model with encrypted PHI fields
        """
        model = PatientModel(
            id=patient.id,
            # Encrypt PHI fields
            _first_name=EncryptedPHI(
                plaintext=patient.first_name, 
                encryption_service=self._encryption_service
            ).ciphertext,
            _last_name=EncryptedPHI(
                plaintext=patient.last_name, 
                encryption_service=self._encryption_service
            ).ciphertext,
            _date_of_birth=EncryptedPHI(
                plaintext=patient.date_of_birth.isoformat(), 
                encryption_service=self._encryption_service
            ).ciphertext,
            # More fields...
        )
        return model
    
    def _model_to_entity(self, model: PatientModel) -> Patient:
        """
        Convert database model to domain entity with PHI decryption.
        
        Args:
            model: SQLAlchemy model
            
        Returns:
            Domain entity with decrypted PHI fields
        """
        return Patient(
            id=model.id,
            # Decrypt PHI fields
            first_name=EncryptedPHI(
                ciphertext=model._first_name, 
                encryption_service=self._encryption_service
            ).get_plaintext(),
            last_name=EncryptedPHI(
                ciphertext=model._last_name, 
                encryption_service=self._encryption_service
            ).get_plaintext(),
            date_of_birth=date.fromisoformat(
                EncryptedPHI(
                    ciphertext=model._date_of_birth, 
                    encryption_service=self._encryption_service
                ).get_plaintext()
            ),
            # More fields...
        )
```

## Unit of Work Pattern

The Unit of Work pattern manages transactions across multiple repositories:

```python
# app/domain/interfaces/unit_of_work.py
from abc import ABC, abstractmethod
from app.domain.interfaces.repositories.patient_repository_interface import IPatientRepository
from app.domain.interfaces.repositories.medical_record_repository_interface import IMedicalRecordRepository

class IUnitOfWork(ABC):
    """
    Interface for the Unit of Work pattern.
    
    Manages database transactions across multiple repositories,
    ensuring atomicity and consistency of operations.
    """
    
    @property
    @abstractmethod
    def patient_repository(self) -> IPatientRepository:
        """Get the patient repository."""
        pass
    
    @property
    @abstractmethod
    def medical_record_repository(self) -> IMedicalRecordRepository:
        """Get the medical record repository."""
        pass
    
    @abstractmethod
    async def commit(self) -> None:
        """Commit the transaction."""
        pass
    
    @abstractmethod
    async def rollback(self) -> None:
        """Rollback the transaction."""
        pass
    
    @abstractmethod
    async def __aenter__(self):
        """Start a new transaction."""
        pass
    
    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """End the transaction."""
        pass
```

### Unit of Work Implementation

The SQLAlchemy implementation of the Unit of Work pattern:

```python
# app/infrastructure/persistence/unit_of_work.py
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.interfaces.unit_of_work import IUnitOfWork
from app.domain.interfaces.repositories.patient_repository_interface import IPatientRepository
from app.domain.interfaces.repositories.medical_record_repository_interface import IMedicalRecordRepository
from app.infrastructure.persistence.repositories.sqlalchemy_patient_repository import SQLAlchemyPatientRepository
from app.infrastructure.persistence.repositories.sqlalchemy_medical_record_repository import SQLAlchemyMedicalRecordRepository
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.core.interfaces.services.encryption_service_interface import IEncryptionService

class SQLAlchemyUnitOfWork(IUnitOfWork):
    """SQLAlchemy implementation of Unit of Work pattern."""
    
    def __init__(
        self, 
        session: AsyncSession,
        audit_logger: IAuditLogger,
        encryption_service: IEncryptionService
    ):
        """Initialize with session and required services."""
        self._session = session
        self._audit_logger = audit_logger
        self._encryption_service = encryption_service
        
        # Lazy-initialized repositories
        self._patient_repository = None
        self._medical_record_repository = None
    
    @property
    def patient_repository(self) -> IPatientRepository:
        """Get the patient repository."""
        if self._patient_repository is None:
            self._patient_repository = SQLAlchemyPatientRepository(
                self._session, 
                self._audit_logger,
                self._encryption_service
            )
        return self._patient_repository
    
    @property
    def medical_record_repository(self) -> IMedicalRecordRepository:
        """Get the medical record repository."""
        if self._medical_record_repository is None:
            self._medical_record_repository = SQLAlchemyMedicalRecordRepository(
                self._session, 
                self._audit_logger,
                self._encryption_service
            )
        return self._medical_record_repository
    
    async def commit(self) -> None:
        """Commit the transaction."""
        await self._session.commit()
    
    async def rollback(self) -> None:
        """Rollback the transaction."""
        await self._session.rollback()
    
    async def __aenter__(self):
        """Start a new transaction."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        End the transaction.
        
        Commits if no exception occurred, otherwise rolls back.
        """
        try:
            if exc_type is None:
                await self.commit()
            else:
                await self.rollback()
        except Exception:
            await self.rollback()
            raise
```

## Usage in Application Services

Application services use repositories via the Unit of Work pattern:

```python
# app/application/services/patient_service.py
from app.domain.interfaces.unit_of_work import IUnitOfWork
from app.domain.entities.patient import Patient
from app.domain.entities.medical_record import MedicalRecord
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.domain.value_objects.user_id import UserId
from uuid import UUID

class PatientService:
    """Service for patient-related operations."""
    
    def __init__(self, unit_of_work: IUnitOfWork, audit_logger: IAuditLogger):
        """Initialize with Unit of Work and audit logger."""
        self._uow = unit_of_work
        self._audit_logger = audit_logger
    
    async def create_patient_with_medical_history(
        self,
        patient_data: dict,
        medical_records: list[dict],
        created_by: UserId
    ) -> Patient:
        """
        Create a new patient with medical records in a single transaction.
        
        This method demonstrates the Unit of Work pattern with proper
        HIPAA-compliant handling of PHI across multiple repositories.
        
        Args:
            patient_data: Patient data dictionary
            medical_records: List of medical record dictionaries
            created_by: ID of the user creating the records
            
        Returns:
            Created patient entity
        """
        # Create patient entity from data
        patient = Patient.create_from_dict(patient_data)
        
        async with self._uow:
            try:
                # Create patient in repository
                created_patient = await self._uow.patient_repository.create(
                    patient=patient,
                    created_by=created_by
                )
                
                # Create medical records
                for record_data in medical_records:
                    record = MedicalRecord.create_from_dict(
                        {**record_data, "patient_id": created_patient.id}
                    )
                    
                    await self._uow.medical_record_repository.create(
                        medical_record=record,
                        created_by=created_by
                    )
                
                # Log the complete operation
                await self._audit_logger.log_security_event(
                    event_type="patient_created",
                    user_id=str(created_by),
                    description=f"Created patient with {len(medical_records)} medical records",
                    severity="INFO"
                )
                
                return created_patient
                
            except Exception as e:
                # Log error without exposing PHI
                await self._audit_logger.log_security_event(
                    event_type="creation_error",
                    user_id=str(created_by),
                    description=f"Error creating patient with medical history: {type(e).__name__}",
                    severity="ERROR"
                )
                # Re-raise with sanitized message
                raise ApplicationError(
                    message="Failed to create patient with medical history",
                    code="PATIENT_CREATION_ERROR"
                )
```

## Dependency Injection Setup

The repositories and Unit of Work are configured via dependency injection:

```python
# app/presentation/api/dependencies/repositories.py
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.presentation.api.dependencies.database import get_db
from app.domain.interfaces.repositories.patient_repository_interface import IPatientRepository
from app.infrastructure.persistence.repositories.sqlalchemy_patient_repository import SQLAlchemyPatientRepository
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.core.interfaces.services.encryption_service_interface import IEncryptionService
from app.presentation.api.dependencies.services import get_audit_logger, get_encryption_service

def get_patient_repository(
    db: AsyncSession = Depends(get_db),
    audit_logger: IAuditLogger = Depends(get_audit_logger),
    encryption_service: IEncryptionService = Depends(get_encryption_service)
) -> IPatientRepository:
    """Dependency provider for patient repository."""
    return SQLAlchemyPatientRepository(db, audit_logger, encryption_service)
```

```python
# app/presentation/api/dependencies/unit_of_work.py
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.presentation.api.dependencies.database import get_db
from app.domain.interfaces.unit_of_work import IUnitOfWork
from app.infrastructure.persistence.unit_of_work import SQLAlchemyUnitOfWork
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.core.interfaces.services.encryption_service_interface import IEncryptionService
from app.presentation.api.dependencies.services import get_audit_logger, get_encryption_service

def get_unit_of_work(
    db: AsyncSession = Depends(get_db),
    audit_logger: IAuditLogger = Depends(get_audit_logger),
    encryption_service: IEncryptionService = Depends(get_encryption_service)
) -> IUnitOfWork:
    """Dependency provider for Unit of Work."""
    return SQLAlchemyUnitOfWork(db, audit_logger, encryption_service)
```

## Database Migration Strategy

The system uses Alembic for database migrations:

```python
# migrations/env.py
from alembic import context
from sqlalchemy import engine_from_config, pool
from app.infrastructure.persistence.models.base import Base
from app.core.config import settings

# Import all models to ensure they're included in migrations
from app.infrastructure.persistence.models import (
    patient_model,
    medical_record_model,
    medication_model,
    biometric_reading_model,
    user_model,
    audit_log_model
)

# Configuration section
config = context.config
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
target_metadata = Base.metadata

# Define migration functions
def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    # ...implementation...

def run_migrations_online():
    """Run migrations in 'online' mode."""
    # ...implementation...
```

## HIPAA Audit Logging

All PHI access is logged through the audit system:

```python
# app/infrastructure/logging/audit_logger_service.py
from datetime import datetime
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.domain.interfaces.repositories.audit_log_repository_interface import IAuditLogRepository
from app.domain.entities.audit_log import AuditLog, AuditLogType, AuditLogSeverity
from typing import Dict, Any, Optional

class AuditLoggerService(IAuditLogger):
    """Service for HIPAA-compliant audit logging."""
    
    def __init__(self, audit_log_repository: IAuditLogRepository):
        """Initialize with audit log repository."""
        self._audit_log_repository = audit_log_repository
    
    async def log_phi_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log PHI access for HIPAA compliance.
        
        Args:
            user_id: ID of the user accessing PHI
            resource_type: Type of resource being accessed
            resource_id: ID of the resource being accessed
            action: Action performed (view, create, update, delete)
            reason: Reason for PHI access (optional)
            metadata: Additional context (optional)
        """
        audit_log = AuditLog(
            timestamp=datetime.utcnow(),
            type=AuditLogType.PHI_ACCESS,
            user_id=user_id,
            description=f"{action.upper()} operation on {resource_type} {resource_id}",
            severity=AuditLogSeverity.INFO,
            metadata={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "action": action,
                "reason": reason,
                **(metadata or {})
            }
        )
        
        await self._audit_log_repository.create(audit_log)
```

## HIPAA Compliance Testing

The database access layer includes HIPAA compliance tests:

```python
# app/tests/infrastructure/repositories/test_patient_repository_hipaa.py
import pytest
from unittest.mock import Mock, AsyncMock
from uuid import uuid4
from app.domain.entities.patient import Patient
from app.infrastructure.persistence.repositories.sqlalchemy_patient_repository import SQLAlchemyPatientRepository

@pytest.mark.asyncio
async def test_patient_repository_logs_phi_access():
    """Test that PHI access is logged when accessing patient data."""
    # Setup
    session_mock = AsyncMock()
    session_mock.execute.return_value.scalars.return_value.first.return_value = Mock()
    
    audit_logger_mock = AsyncMock()
    encryption_service_mock = Mock()
    
    repo = SQLAlchemyPatientRepository(
        session=session_mock,
        audit_logger=audit_logger_mock,
        encryption_service=encryption_service_mock
    )
    
    # Execute
    patient_id = uuid4()
    user_id = uuid4()
    await repo.get_by_id(patient_id, user_id)
    
    # Verify
    audit_logger_mock.log_phi_access.assert_called_once()
    call_args = audit_logger_mock.log_phi_access.call_args[1]
    assert call_args["user_id"] == str(user_id)
    assert call_args["resource_type"] == "patient"
    assert call_args["resource_id"] == str(patient_id)
    assert call_args["action"] == "view"
```

## Best Practices for HIPAA-Compliant Database Access

### 1. Encryption Management

- Always encrypt PHI fields before storage
- Use the `EncryptedPHI` value object for consistent handling
- Never store encryption keys in the database
- Use key rotation for long-term security

### 2. Proper Audit Logging

- Log all PHI access with user context
- Include access reason when available
- Log failed access attempts
- Ensure audit logs are immutable

### 3. Minimizing PHI Exposure

- Only retrieve PHI fields when necessary
- Use projections to limit fields returned
- Implement "need to know" access control
- Clear PHI from memory when no longer needed

### 4. Secure Error Handling

- Never include PHI in error messages
- Use domain exceptions that sanitize details
- Log original errors securely
- Return generic errors to clients

### 5. Transactions and Consistency

- Use Unit of Work pattern for transactions
- Ensure all or nothing operations with PHI
- Implement proper rollback on errors
- Verify data integrity after operations

## Database Configuration for HIPAA Compliance

```python
# app/core/config/database_settings.py
from pydantic import BaseSettings, PostgresDsn

class DatabaseSettings(BaseSettings):
    """Database configuration with HIPAA compliance settings."""
    
    # Connection settings
    DATABASE_URL: PostgresDsn
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_TIMEOUT: int = 30
    
    # HIPAA-related settings
    ENABLE_FIELD_ENCRYPTION: bool = True
    AUDIT_ALL_PHI_ACCESS: bool = True
    AUDIT_LOG_RETENTION_DAYS: int = 365  # 1 year retention for HIPAA
    DATABASE_SSL_REQUIRED: bool = True  # Enforce SSL for data in transit
    
    # Connection pooling
    DB_POOL_RECYCLE: int = 1800  # 30 minutes
    
    # Query settings
    SQL_ECHO: bool = False  # Set to True for debugging only
    
    class Config:
        """Pydantic config."""
        env_prefix = "CLARITY_"
        env_file = ".env"
```

## Conclusion

The Clarity AI Backend implements a HIPAA-compliant database access layer through:

1. **Repository Pattern**: Abstracting database operations behind domain interfaces
2. **Field-Level Encryption**: Protecting PHI at rest with proper encryption
3. **Comprehensive Audit Logging**: Tracking all PHI access for compliance
4. **Unit of Work Pattern**: Maintaining transaction integrity across repositories
5. **Clean Architecture**: Separating domain logic from database implementation details

By following these patterns and practices, the system maintains HIPAA compliance while providing a clean, maintainable architecture for handling psychiatric data in a secure manner.
