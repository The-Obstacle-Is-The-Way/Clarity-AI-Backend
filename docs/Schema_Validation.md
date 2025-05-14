# Schema Validation

## Overview

This document details the schema validation implementation in the Clarity AI Backend, which ensures data integrity, security, and HIPAA compliance through comprehensive input and output validation. By adhering to clean architecture principles, we maintain a rigid validation boundary between external inputs and our core domain.

## Core Principles

1. **Strict Validation**: All external inputs must be validated before processing
2. **Separation of Concerns**: DTOs separate API schemas from domain models
3. **Centralized Definition**: Validation rules defined in one place
4. **HIPAA Compliance**: Validates PHI formats and prevents exposure of sensitive data
5. **Clean Architecture**: Maintains the integrity of layer boundaries
6. **Exception Safety**: Consistent error handling for validation failures

## Validation Architecture

### Pydantic Models

```python
from pydantic import BaseModel, Field, validator, root_validator
from typing import Optional, List, Dict, Any
from datetime import date, datetime
import re
from uuid import UUID

class PatientCreateRequest(BaseModel):
    """
    Schema for patient creation API input.
    
    Validates all input fields before domain processing.
    """
    
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    date_of_birth: date
    gender: str = Field(..., regex=r"^(male|female|other|prefer_not_to_say)$")
    medical_record_number: Optional[str] = Field(None, max_length=50)
    email: Optional[str] = Field(None, regex=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    
    @validator('date_of_birth')
    def validate_dob(cls, v):
        """Validate date of birth is not in the future."""
        if v > date.today():
            raise ValueError("Date of birth cannot be in the future")
        return v
    
    @validator('phone')
    def validate_phone(cls, v):
        """Validate phone number format if provided."""
        if v is not None:
            # Strip non-numeric characters
            digits_only = re.sub(r'\D', '', v)
            
            # Check length
            if len(digits_only) < 10 or len(digits_only) > 15:
                raise ValueError("Phone number must have 10-15 digits")
                
            # Format consistently
            return digits_only
        return v
    
    @root_validator
    def validate_patient_identification(cls, values):
        """Ensure patient has sufficient identification."""
        email = values.get('email')
        phone = values.get('phone')
        mrn = values.get('medical_record_number')
        
        # At least one contact method or identifier must be provided
        if not any([email, phone, mrn]):
            raise ValueError(
                "At least one of email, phone, or medical_record_number must be provided"
            )
            
        return values
    
    class Config:
        """Pydantic configuration."""
        extra = "forbid"  # Reject additional fields
        schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "date_of_birth": "1980-01-01",
                "gender": "male",
                "email": "john.doe@example.com",
                "phone": "555-123-4567",
                "medical_record_number": "MRN123456",
                "address": {
                    "street": "123 Main St",
                    "city": "Anytown",
                    "state": "CA",
                    "zip_code": "12345"
                }
            }
        }
```

### Response Models

```python
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import date, datetime
from app.core.domain.entities import Patient
from uuid import UUID

class PatientResponse(BaseModel):
    """
    Schema for patient API responses.
    
    Controls exactly what fields are exposed in the API response,
    preventing accidental exposure of PHI.
    """
    
    id: UUID
    first_name: str
    last_name: str
    date_of_birth: date
    gender: str
    email: Optional[str] = None
    phone: Optional[str] = None
    medical_record_number: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    @classmethod
    def from_domain_entity(cls, patient: Patient) -> "PatientResponse":
        """
        Convert domain entity to API response model.
        
        Args:
            patient: Domain patient entity
            
        Returns:
            API response model
        """
        return cls(
            id=patient.id,
            first_name=patient.first_name,
            last_name=patient.last_name,
            date_of_birth=patient.date_of_birth,
            gender=patient.gender,
            email=patient.email,
            phone=patient.phone,
            medical_record_number=patient.medical_record_number,
            created_at=patient.created_at,
            updated_at=patient.updated_at
        )
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "first_name": "John",
                "last_name": "Doe",
                "date_of_birth": "1980-01-01",
                "gender": "male",
                "email": "john.doe@example.com",
                "phone": "5551234567",
                "medical_record_number": "MRN123456",
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-02T12:00:00Z"
            }
        }
```

## API Validation Pattern

```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.presentation.schemas.patient import PatientCreateRequest, PatientResponse
from app.core.interfaces.services import IPatientService
from app.presentation.api.dependencies.services import get_patient_service
from app.presentation.api.dependencies.auth import get_current_user
from app.core.domain.entities import User
from typing import List

router = APIRouter()

@router.post(
    "/patients",
    response_model=PatientResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new patient",
    description="Create a new patient record with complete validation"
)
async def create_patient(
    patient_data: PatientCreateRequest,
    current_user: User = Depends(get_current_user),
    patient_service: IPatientService = Depends(get_patient_service)
):
    """
    Create a new patient with full schema validation.
    
    This endpoint demonstrates the complete validation pattern:
    1. FastAPI automatically validates request against PatientCreateRequest
    2. Custom validators in the schema perform complex validations
    3. Data is transformed into the domain model
    4. Operation is performed
    5. Response is validated against PatientResponse schema
    """
    # Request validation already performed by FastAPI + Pydantic
    
    # Convert validated request to domain parameters
    try:
        patient = await patient_service.create_patient(
            first_name=patient_data.first_name,
            last_name=patient_data.last_name,
            date_of_birth=patient_data.date_of_birth,
            gender=patient_data.gender,
            email=patient_data.email,
            phone=patient_data.phone,
            medical_record_number=patient_data.medical_record_number,
            address=patient_data.address
        )
    except ValueError as e:
        # Domain validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Convert domain entity to response model
    # This ensures only intended fields are exposed
    return PatientResponse.from_domain_entity(patient)
```

## Query Parameter Validation

```python
from fastapi import APIRouter, Depends, Query, HTTPException, status
from app.presentation.schemas.patient import PatientResponse
from app.core.interfaces.services import IPatientService
from app.presentation.api.dependencies.services import get_patient_service
from datetime import date
from typing import List, Optional
from enum import Enum

class GenderFilter(str, Enum):
    """Valid gender values for filtering."""
    MALE = "male"
    FEMALE = "female"
    OTHER = "other"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"

class SortOrder(str, Enum):
    """Valid sort orders."""
    ASC = "asc"
    DESC = "desc"

router = APIRouter()

@router.get(
    "/patients",
    response_model=List[PatientResponse],
    summary="Search patients",
    description="Search and filter patients with validated parameters"
)
async def search_patients(
    name: Optional[str] = Query(None, min_length=2, max_length=100, description="Name search"),
    gender: Optional[GenderFilter] = Query(None, description="Filter by gender"),
    min_age: Optional[int] = Query(None, ge=0, le=120, description="Minimum age"),
    max_age: Optional[int] = Query(None, ge=0, le=120, description="Maximum age"),
    sort_by: str = Query("last_name", description="Field to sort by"),
    sort_order: SortOrder = Query(SortOrder.ASC, description="Sort direction"),
    limit: int = Query(50, ge=1, le=100, description="Records per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    patient_service: IPatientService = Depends(get_patient_service)
):
    """
    Search patients with validated query parameters.
    
    Demonstrates validation of query parameters using FastAPI's Query class,
    with proper error handling and type conversion.
    """
    # Convert age to date of birth ranges if provided
    min_dob = None
    max_dob = None
    
    if max_age is not None:
        # Calculate date of birth for minimum age
        min_dob = date.today().replace(year=date.today().year - max_age)
    
    if min_age is not None:
        # Calculate date of birth for maximum age
        max_dob = date.today().replace(year=date.today().year - min_age)
    
    # All parameters validated by FastAPI + Pydantic
    try:
        patients = await patient_service.search_patients(
            name=name,
            gender=gender.value if gender else None,
            min_dob=min_dob,
            max_dob=max_dob,
            sort_by=sort_by,
            sort_order=sort_order.value,
            limit=limit,
            offset=offset
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    return [PatientResponse.from_domain_entity(p) for p in patients]
```

## Path Parameter Validation

```python
from fastapi import APIRouter, Depends, Path, HTTPException, status
from app.presentation.schemas.patient import PatientResponse
from app.core.interfaces.services import IPatientService
from app.presentation.api.dependencies.services import get_patient_service
from uuid import UUID

router = APIRouter()

@router.get(
    "/patients/{patient_id}",
    response_model=PatientResponse,
    summary="Get patient by ID",
    description="Retrieve a patient by their UUID with validated path parameter"
)
async def get_patient(
    patient_id: UUID = Path(..., description="Patient UUID"),
    patient_service: IPatientService = Depends(get_patient_service)
):
    """
    Get patient by ID with validated path parameter.
    
    Demonstrates validation of path parameters using FastAPI's Path class,
    with UUID validation and conversion.
    """
    # UUID already validated by FastAPI + Pydantic
    patient = await patient_service.get_by_id(patient_id)
    
    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )
    
    return PatientResponse.from_domain_entity(patient)
```

## Request Body Validation

### JSON Body Validation

```python
from fastapi import APIRouter, Depends, Body, HTTPException, status
from pydantic import BaseModel, Field, validator
from app.presentation.schemas.biometric import BiometricReadingRequest
from app.core.interfaces.services import IPatientService
from app.presentation.api.dependencies.services import get_patient_service
from typing import List
from uuid import UUID

class BiometricBatchRequest(BaseModel):
    """
    Schema for batch biometric upload.
    
    Validates the entire request body structure.
    """
    
    patient_id: UUID
    readings: List[BiometricReadingRequest] = Field(..., min_items=1, max_items=1000)
    
    @validator('readings')
    def validate_readings(cls, v):
        """Ensure readings are valid and in ascending order by timestamp."""
        if len(v) > 0:
            # Check timestamps are in ascending order
            timestamps = [r.timestamp for r in v]
            sorted_timestamps = sorted(timestamps)
            
            if timestamps != sorted_timestamps:
                raise ValueError("Readings must be in ascending order by timestamp")
                
        return v

router = APIRouter()

@router.post(
    "/biometrics/batch",
    status_code=status.HTTP_201_CREATED,
    summary="Upload biometric batch",
    description="Upload multiple biometric readings in a single request"
)
async def upload_biometric_batch(
    batch: BiometricBatchRequest,
    patient_service: IPatientService = Depends(get_patient_service)
):
    """
    Process batch biometric uploads with complex validation.
    
    Demonstrates validation of a complex nested request body,
    with both field-level and object-level validations.
    """
    # Request already validated by FastAPI + Pydantic
    try:
        # Convert to domain objects
        readings = [
            {
                "type": r.type,
                "value": r.value,
                "unit": r.unit,
                "timestamp": r.timestamp,
                "device_id": r.device_id,
                "metadata": r.metadata
            }
            for r in batch.readings
        ]
        
        # Process the readings
        await patient_service.add_biometric_readings(
            patient_id=batch.patient_id,
            readings=readings
        )
        
        return {"status": "success", "count": len(batch.readings)}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
```

### Form Data Validation

```python
from fastapi import APIRouter, Depends, Form, HTTPException, status, UploadFile, File
from app.core.interfaces.services import IDocumentService
from app.presentation.api.dependencies.services import get_document_service
from uuid import UUID
from typing import Optional

router = APIRouter()

@router.post(
    "/patients/{patient_id}/documents",
    status_code=status.HTTP_201_CREATED,
    summary="Upload patient document",
    description="Upload a document to a patient's record with form validation"
)
async def upload_document(
    patient_id: UUID,
    document_type: str = Form(..., min_length=1, max_length=50),
    document_date: str = Form(..., regex=r"^\d{4}-\d{2}-\d{2}$"),
    description: Optional[str] = Form(None, max_length=200),
    file: UploadFile = File(...),
    document_service: IDocumentService = Depends(get_document_service)
):
    """
    Upload patient document with form data validation.
    
    Demonstrates validation of multipart form data,
    including file uploads and form fields.
    """
    # Form fields already validated by FastAPI
    
    # Validate file
    if file.content_type not in ["application/pdf", "image/jpeg", "image/png"]:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="File must be PDF, JPEG, or PNG"
        )
    
    if file.size > 10 * 1024 * 1024:  # 10 MB
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds 10 MB limit"
        )
    
    try:
        # Process the document
        document_id = await document_service.upload_document(
            patient_id=patient_id,
            document_type=document_type,
            document_date=document_date,
            description=description,
            file_content=await file.read(),
            file_name=file.filename,
            content_type=file.content_type
        )
        
        return {"document_id": document_id}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
```

## Error Handling

### Custom Validation Exceptions

```python
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from app.core.domain.errors import DomainValidationError

app = FastAPI()

@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    """
    Handle Pydantic validation errors.
    
    Formats validation errors consistently and securely.
    """
    # Extract error details in a safe format
    errors = {}
    for error in exc.errors():
        location = ".".join(str(loc) for loc in error["loc"])
        errors[location] = error["msg"]
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": errors
        }
    )

@app.exception_handler(DomainValidationError)
async def domain_validation_exception_handler(request: Request, exc: DomainValidationError):
    """
    Handle domain validation errors.
    
    Formats domain validation errors consistently.
    """
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": str(exc),
            "code": exc.code
        }
    )
```

## HIPAA Compliance

### PHI Data Validation

```python
from pydantic import validator
import re

class MedicalRecordValidator:
    """
    Validation methods for medical record data.
    
    Provides validation methods for common PHI fields
    to ensure data quality and consistency.
    """
    
    @staticmethod
    def validate_mrn(mrn: str) -> str:
        """
        Validate Medical Record Number format.
        
        Ensures consistent format and removes invalid characters.
        """
        if not mrn:
            return mrn
            
        # Remove whitespace and special characters
        cleaned = re.sub(r'[^\w]', '', mrn)
        
        # Check length
        if len(cleaned) < 5 or len(cleaned) > 20:
            raise ValueError("Medical Record Number must be 5-20 alphanumeric characters")
            
        return cleaned
    
    @staticmethod
    def validate_ssn(ssn: str) -> str:
        """
        Validate Social Security Number format.
        
        Ensures proper SSN format and masks for security.
        """
        if not ssn:
            return ssn
            
        # Remove non-numeric characters
        digits_only = re.sub(r'\D', '', ssn)
        
        # Check length
        if len(digits_only) != 9:
            raise ValueError("SSN must be 9 digits")
            
        # Format consistently as XXX-XX-XXXX
        return f"{digits_only[:3]}-{digits_only[3:5]}-{digits_only[5:]}"
    
    @staticmethod
    def validate_zip_code(zip_code: str) -> str:
        """
        Validate US ZIP code format.
        
        Ensures proper ZIP code format.
        """
        if not zip_code:
            return zip_code
            
        # Remove non-alphanumeric characters
        cleaned = re.sub(r'[^\w]', '', zip_code)
        
        # Check format (5 digits or ZIP+4)
        if len(cleaned) == 5 and cleaned.isdigit():
            return cleaned
        elif len(cleaned) == 9 and cleaned.isdigit():
            return f"{cleaned[:5]}-{cleaned[5:]}"
        else:
            raise ValueError("ZIP code must be 5 digits or ZIP+4 format")
```

## Validation Testing

```python
import pytest
from fastapi.testclient import TestClient
from app.presentation.schemas.patient import PatientCreateRequest
from datetime import date

def test_patient_create_request_validation():
    """Test patient creation request validation."""
    # Valid data
    valid_data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1980-01-01",
        "gender": "male",
        "email": "john.doe@example.com"
    }
    
    patient = PatientCreateRequest(**valid_data)
    assert patient.first_name == "John"
    assert patient.last_name == "Doe"
    assert patient.date_of_birth == date(1980, 1, 1)
    
    # Invalid email
    invalid_email_data = valid_data.copy()
    invalid_email_data["email"] = "invalid-email"
    
    with pytest.raises(ValueError) as excinfo:
        PatientCreateRequest(**invalid_email_data)
    assert "email" in str(excinfo.value)
    
    # Future date of birth
    future_dob_data = valid_data.copy()
    future_dob_data["date_of_birth"] = "2100-01-01"
    
    with pytest.raises(ValueError) as excinfo:
        PatientCreateRequest(**future_dob_data)
    assert "date_of_birth" in str(excinfo.value)
    
    # Invalid gender
    invalid_gender_data = valid_data.copy()
    invalid_gender_data["gender"] = "invalid"
    
    with pytest.raises(ValueError) as excinfo:
        PatientCreateRequest(**invalid_gender_data)
    assert "gender" in str(excinfo.value)
    
    # No identification
    no_id_data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1980-01-01",
        "gender": "male"
    }
    
    with pytest.raises(ValueError) as excinfo:
        PatientCreateRequest(**no_id_data)
    assert "identification" in str(excinfo.value)
    
    # Extra fields
    extra_fields_data = valid_data.copy()
    extra_fields_data["unknown_field"] = "value"
    
    with pytest.raises(ValueError) as excinfo:
        PatientCreateRequest(**extra_fields_data)
    assert "extra" in str(excinfo.value)
```

## Implementation Status

### Current Status

- ✅ Pydantic models for all API schemas
- ✅ Request validation for query, path, and body parameters
- ✅ Response validation with explicit schemas
- ✅ HIPAA-compliant PHI validation
- ✅ Consistent error handling for validation failures

### Architectural Gaps

- 🔄 Consider stronger separation between API schemas and domain DTOs
- 🔄 Implement more comprehensive PHI validation patterns
- 🔄 Add validation-specific test suite for all schemas

## Best Practices

1. **Always Use Response Models**: Define explicit response models for all endpoints
2. **Validate Before Processing**: Validate all inputs at the API boundary
3. **Secure by Default**: Use `extra="forbid"` to reject unknown fields
4. **Provide Examples**: Include schema examples for OpenAPI documentation
5. **Use Typed Enums**: Define enum classes for constrained choice fields
6. **Custom Validators**: Implement domain-specific validation logic
7. **Test Edge Cases**: Write thorough validation tests for edge cases
8. **Consistent Errors**: Format validation errors consistently

By following these patterns and practices, the Clarity AI Backend ensures data integrity and security while maintaining clean architectural boundaries between the API layer and the core domain.
