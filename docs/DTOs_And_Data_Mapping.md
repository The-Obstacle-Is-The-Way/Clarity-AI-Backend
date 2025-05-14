# DTOs & Data Mapping Guide

## Overview

This document outlines the implementation of Data Transfer Objects (DTOs) and data mapping patterns in the Clarity AI Backend. These patterns are essential for maintaining clean separation between layers, ensuring type safety, and facilitating the transformation of data as it flows through the system.

## Core Principles

1. **Boundary Separation**: DTOs create clear boundaries between architectural layers
2. **Data Integrity**: DTOs enforce validation at layer boundaries with Pydantic
3. **Immutability**: DTOs are immutable to prevent unexpected state changes
4. **HIPAA Compliance**: DTOs help enforce PHI access controls and sanitization

## DTO Types

The system implements several categories of DTOs:

### Request DTOs

Used to receive and validate input data from API clients:

```python
from pydantic import BaseModel, Field, validator
from datetime import date
from typing import Optional

class PatientCreateRequestDTO(BaseModel):
    """DTO for creating a new patient record."""
    
    name: str = Field(..., min_length=2, max_length=100)
    date_of_birth: date
    medical_record_number: str = Field(..., pattern=r'^MRN\d{6}$')
    notes: Optional[str] = None
    
    @validator('date_of_birth')
    def validate_birth_date(cls, value):
        if value > date.today():
            raise ValueError("Date of birth cannot be in the future")
        return value
    
    class Config:
        schema_extra = {
            "example": {
                "name": "Jane Doe",
                "date_of_birth": "1985-05-15",
                "medical_record_number": "MRN123456",
                "notes": "Initial consultation scheduled"
            }
        }
```

### Response DTOs

Used to format and return data from the system to API clients:

```python
from pydantic import BaseModel
from datetime import date
from typing import List, Optional

class BiometricDataDTO(BaseModel):
    """DTO for biometric measurements."""
    type: str
    value: float
    unit: str
    timestamp: str

class PatientResponseDTO(BaseModel):
    """DTO for patient information returned to clients."""
    id: str
    name: str
    date_of_birth: date
    medical_record_number: str
    biometric_data: Optional[List[BiometricDataDTO]] = None
    
    class Config:
        schema_extra = {
            "example": {
                "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "name": "Jane Doe",
                "date_of_birth": "1985-05-15",
                "medical_record_number": "MRN123456",
                "biometric_data": [
                    {
                        "type": "heart_rate",
                        "value": 72.5,
                        "unit": "bpm",
                        "timestamp": "2023-06-15T14:30:00Z"
                    }
                ]
            }
        }
```

### Internal DTOs

Used for communication between application layers:

```python
from pydantic import BaseModel
from typing import List, Dict, Any

class PatientAnalysisDTO(BaseModel):
    """Internal DTO for patient analysis operations."""
    patient_id: str
    readings: List[Dict[str, Any]]
    analysis_type: str
    user_id: str  # For audit logging
```

## Data Mapping Patterns

### Using Factories for Entity-to-DTO Conversion

```python
from app.core.domain.entities import Patient
from app.application.dtos.patient import PatientResponseDTO

class PatientDTOFactory:
    """Factory for creating Patient DTOs from domain entities."""
    
    @staticmethod
    def create_response_dto(patient: Patient) -> PatientResponseDTO:
        """
        Convert a Patient domain entity to a response DTO.
        
        Args:
            patient: The domain entity to convert
            
        Returns:
            A response DTO populated with patient data
        """
        return PatientResponseDTO(
            id=str(patient.id),
            name=patient.name,
            date_of_birth=patient.date_of_birth,
            medical_record_number=patient.medical_record_number,
            biometric_data=[
                BiometricDataDTO(
                    type=reading.type,
                    value=reading.value,
                    unit=reading.unit,
                    timestamp=reading.timestamp.isoformat()
                )
                for reading in patient.biometric_readings
            ] if patient.biometric_readings else None
        )
```

### Using Mappers for Complex Conversions

```python
from app.core.domain.entities import Patient, BiometricReading
from app.application.dtos import PatientCreateRequestDTO
from app.core.domain.value_objects import PatientId
from uuid import uuid4

class PatientMapper:
    """Handles mapping between Patient DTOs and domain entities."""
    
    @staticmethod
    def to_entity(dto: PatientCreateRequestDTO) -> Patient:
        """
        Convert a request DTO to a domain entity.
        
        Args:
            dto: The request DTO to convert
            
        Returns:
            A new Patient domain entity
        """
        return Patient(
            id=PatientId(str(uuid4())),
            name=dto.name,
            date_of_birth=dto.date_of_birth,
            medical_record_number=dto.medical_record_number,
            notes=dto.notes
        )
    
    @staticmethod
    def update_entity(
        entity: Patient, 
        dto: PatientUpdateRequestDTO
    ) -> Patient:
        """
        Update an existing entity with data from a DTO.
        
        Args:
            entity: The existing entity to update
            dto: The DTO containing update data
            
        Returns:
            The updated entity
        """
        # Create a new entity with updated values
        # This preserves immutability principles
        return Patient(
            id=entity.id,
            name=dto.name if dto.name is not None else entity.name,
            date_of_birth=dto.date_of_birth if dto.date_of_birth is not None else entity.date_of_birth,
            medical_record_number=entity.medical_record_number,  # Immutable field
            notes=dto.notes if dto.notes is not None else entity.notes
        )
```

## PHI Sanitization

DTO processing includes sanitization for HIPAA compliance:

```python
from app.core.domain.entities import Patient
from app.application.dtos import SanitizedPatientResponseDTO

class PHISanitizer:
    """Sanitizes PHI from patient data."""
    
    @staticmethod
    def sanitize_patient(patient: Patient) -> SanitizedPatientResponseDTO:
        """
        Create a sanitized version of patient data with PHI removed.
        
        Args:
            patient: Patient domain entity
            
        Returns:
            Sanitized DTO suitable for non-clinical users
        """
        return SanitizedPatientResponseDTO(
            id=str(patient.id),
            age=patient.calculate_age(),  # Age instead of DOB
            has_biometric_data=bool(patient.biometric_readings)
            # Excludes name, MRN, and other PHI
        )
```

## Pagination and Collection DTOs

```python
from pydantic import BaseModel
from typing import List, Generic, TypeVar, Optional

T = TypeVar('T')

class PaginatedResponseDTO(BaseModel, Generic[T]):
    """Generic paginated response DTO."""
    
    items: List[T]
    total_count: int
    page: int
    page_size: int
    next_page: Optional[int] = None
    previous_page: Optional[int] = None
    
    @classmethod
    def create(
        cls,
        items: List[T],
        total_count: int,
        page: int,
        page_size: int
    ) -> 'PaginatedResponseDTO[T]':
        """
        Create a properly formatted paginated response.
        
        Args:
            items: The items for the current page
            total_count: Total number of items across all pages
            page: Current page number (1-based)
            page_size: Number of items per page
            
        Returns:
            A paginated response DTO
        """
        total_pages = (total_count + page_size - 1) // page_size
        
        return cls(
            items=items,
            total_count=total_count,
            page=page,
            page_size=page_size,
            next_page=page + 1 if page < total_pages else None,
            previous_page=page - 1 if page > 1 else None
        )
```

## DTO Validation and Error Handling

```python
from fastapi import HTTPException, status
from pydantic import ValidationError

def handle_validation_error(error: ValidationError) -> HTTPException:
    """
    Convert a Pydantic validation error to a FastAPI HTTP exception.
    
    Args:
        error: The validation error
        
    Returns:
        An HTTP exception with detailed error information
    """
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={
            "message": "Validation error",
            "errors": [
                {
                    "field": e["loc"][0],
                    "error": e["msg"]
                }
                for e in error.errors()
            ]
        }
    )
```

## Current Implementation Status

1. **Strengths**:
   - Consistent use of Pydantic for validation
   - Clear separation between request and response DTOs
   - Strong typing throughout the system

2. **Gaps**:
   - Inconsistent use of factories vs. direct mapping
   - Occasional tight coupling between DTOs and entities
   - Manual mapping could be improved with automation tools

3. **HIPAA Compliance**:
   - PHI sanitization is implemented but needs more consistent application
   - Audit logging for DTO transformations involving PHI

## Best Practices

1. **Design Guidelines**:
   - Keep DTOs flat and simple
   - Use composition for complex nested structures
   - Include validation at the DTO level
   - Document all fields and validation rules

2. **Performance Considerations**:
   - Use lazy evaluation for expensive transformations
   - Consider caching for frequently used mappings
   - Optimize serialization for large collections

3. **Testing**:
   - Unit test all DTO validations
   - Test boundary conditions and edge cases
   - Verify PHI sanitization works correctly

By following these patterns, we maintain a clean separation between layers while ensuring type safety and facilitating the transformation of data throughout the system.
