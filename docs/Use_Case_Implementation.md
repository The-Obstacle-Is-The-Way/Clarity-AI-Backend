# Use Case Implementation Guide

## Overview

This document provides guidance on implementing use cases in the Clarity AI Backend following clean architecture principles. Use cases represent the application-specific business rules and orchestrate the flow of data to and from entities while satisfying specific business requirements.

## Core Principles

1. **Single Responsibility**: Each use case should handle one specific business operation
2. **Independence**: Use cases should depend only on domain entities and interfaces, not concrete implementations
3. **Pure Business Logic**: Use cases contain business orchestration logic, not infrastructure concerns
4. **Input/Output Boundaries**: Use cases communicate through well-defined DTOs and interfaces

## Structure

### Use Case Interface

```python
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

TInput = TypeVar('TInput')
TOutput = TypeVar('TOutput')

class UseCase(Generic[TInput, TOutput], ABC):
    """Base interface for all use cases in the system."""
    
    @abstractmethod
    async def execute(self, input_dto: TInput) -> TOutput:
        """
        Execute the use case with the provided input data.
        
        Args:
            input_dto: Data required by the use case
            
        Returns:
            Result of the use case execution
        """
        pass
```

### Example Implementation

```python
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId
from app.core.interfaces.repositories import IPatientRepository
from app.core.interfaces.services import IAuditLogger
from app.application.dtos import GetPatientDTO, PatientResponseDTO

class GetPatientUseCase(UseCase[GetPatientDTO, PatientResponseDTO]):
    """Use case for retrieving patient information."""
    
    def __init__(
        self,
        patient_repository: IPatientRepository,
        audit_logger: IAuditLogger
    ):
        self._patient_repository = patient_repository
        self._audit_logger = audit_logger
    
    async def execute(self, input_dto: GetPatientDTO) -> PatientResponseDTO:
        """
        Retrieve patient information by ID.
        
        Args:
            input_dto: Contains patient_id and user_id of the requester
            
        Returns:
            Patient information as a response DTO
            
        Raises:
            PatientNotFoundError: If patient with the specified ID doesn't exist
            UnauthorizedAccessError: If user is not authorized to view this patient
        """
        # Create domain value object from DTO
        patient_id = PatientId(input_dto.patient_id)
        
        # Use repository to retrieve domain entity
        patient = await self._patient_repository.get_by_id(patient_id)
        
        # Domain logic and validation
        if patient is None:
            raise PatientNotFoundError(f"Patient {patient_id} not found")
        
        # Audit logging for HIPAA compliance
        await self._audit_logger.log_phi_access(
            user_id=input_dto.user_id,
            resource_type="Patient",
            resource_id=str(patient_id),
            action="view"
        )
        
        # Transform domain entity to response DTO
        return PatientResponseDTO(
            id=str(patient.id),
            name=patient.name,
            date_of_birth=patient.date_of_birth,
            medical_record_number=patient.medical_record_number
        )
```

## Use Case Registration and Dependency Injection

Use cases are registered and injected via FastAPI's dependency injection system:

```python
from fastapi import Depends
from app.core.interfaces.repositories import IPatientRepository
from app.core.interfaces.services import IAuditLogger
from app.infrastructure.persistence.repositories import get_patient_repository
from app.infrastructure.logging import get_audit_logger

def get_patient_use_case(
    repository: IPatientRepository = Depends(get_patient_repository),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
) -> GetPatientUseCase:
    """Dependency provider for GetPatientUseCase."""
    return GetPatientUseCase(repository, audit_logger)
```

## Architectural Gaps and Best Practices

1. **Current Gaps**:
   - Some use cases access repositories directly rather than through interfaces
   - Inconsistent error handling across use cases
   - Business logic occasionally leaks into API layer

2. **Best Practices**:
   - Always depend on interfaces, never concrete implementations
   - Implement comprehensive input validation
   - Handle all expected exceptions and provide clear error messages
   - Document all pre-conditions, post-conditions, and error scenarios
   - Keep use cases focused on business orchestration, not technical details

## Testing Use Cases

Use cases should be thoroughly tested with unit tests:

```python
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.application.use_cases.patient import GetPatientUseCase
from app.application.dtos import GetPatientDTO
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId

@pytest.fixture
def patient_repository_mock():
    repository = AsyncMock()
    patient = Patient(
        id=PatientId("patient-123"),
        name="John Doe",
        date_of_birth="1980-01-01",
        medical_record_number="MRN12345"
    )
    repository.get_by_id.return_value = patient
    return repository

@pytest.fixture
def audit_logger_mock():
    return AsyncMock()

@pytest.fixture
def use_case(patient_repository_mock, audit_logger_mock):
    return GetPatientUseCase(patient_repository_mock, audit_logger_mock)

async def test_get_patient_success(use_case, patient_repository_mock, audit_logger_mock):
    # Arrange
    input_dto = GetPatientDTO(patient_id="patient-123", user_id="user-456")
    
    # Act
    result = await use_case.execute(input_dto)
    
    # Assert
    patient_repository_mock.get_by_id.assert_called_once()
    audit_logger_mock.log_phi_access.assert_called_once()
    assert result.id == "patient-123"
    assert result.name == "John Doe"
```

## Using Use Cases in API Endpoints

```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.application.use_cases.patient import GetPatientUseCase
from app.application.dtos import GetPatientDTO, PatientResponseDTO
from app.core.domain.errors import PatientNotFoundError

router = APIRouter()

@router.get(
    "/patients/{patient_id}",
    response_model=PatientResponseDTO,
    summary="Get patient information"
)
async def get_patient(
    patient_id: str,
    current_user_id: str = Depends(get_current_user_id),
    use_case: GetPatientUseCase = Depends(get_patient_use_case)
):
    """Get detailed patient information."""
    try:
        return await use_case.execute(
            GetPatientDTO(
                patient_id=patient_id,
                user_id=current_user_id
            )
        )
    except PatientNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
```

By following these guidelines, we ensure that use cases remain focused on business requirements while maintaining clean separation of concerns and adherence to SOLID principles.
