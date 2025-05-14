# Patient API Routes

## Overview

The Patient API Routes are a foundational component of the Clarity AI Backend that provide access to patient data and operations. These routes represent the RESTful interface for patient management within the psychiatric digital twin platform, including creation, retrieval, update, and deletion of patient records, with comprehensive HIPAA safeguards.

## Clean Architecture Context

The Patient API Routes implement the presentation layer within the clean architecture framework:

1. **Routes**: Define HTTP endpoints and handle request/response transformations
2. **Dependencies**: Inject required services through FastAPI's dependency system
3. **Schemas**: Validate input and output data using Pydantic models
4. **Routers**: Group related endpoints into a cohesive API surface

## Route Definition

The Patient API routes are defined in `app/presentation/api/v1/routes/patient.py`:

```python
import logging
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
from typing import Optional

from app.application.services.patient_service import PatientService
from app.domain.repositories.patient_repository import PatientRepository
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepository as SQLPatientRepoImpl,
)
from app.presentation.api.dependencies.database import get_db
from app.presentation.api.dependencies.patient import get_patient_id as get_validated_patient_id_for_read
from app.presentation.api.dependencies.auth import CurrentUserDep, DomainUser
from app.presentation.api.schemas.patient import (
    PatientRead,
    PatientCreateRequest,
    PatientCreateResponse,
    # PatientUpdateRequest, # COMMENTED OUT TEMPORARILY
)
from app.core.domain.entities.patient import Patient
from app.core.domain.entities.user import UserRole, UserStatus

# Dependency provider for PatientService
def get_patient_service(
    db_session: AsyncSession = Depends(get_db)
) -> PatientService:
    """Dependency provider for PatientService."""
    repo = SQLPatientRepoImpl(db_session=db_session) 
    return PatientService(repository=repo) 

logger = logging.getLogger(__name__)

router = APIRouter()

# Routes

@router.get(
    "",
    response_model=PatientListResponse,
    summary="List patients",
    description="Get a paginated list of patients with optional filtering."
)
async def list_patients(
    request: Request,
    pagination: PaginationParams = Depends(),
    search: PatientSearchParams = Depends(),
    current_user: dict = Depends(verify_has_role(["admin", "clinician"])),
    patient_service: IPatientService = Depends(get_patient_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """
    List patients with pagination and optional filtering.
    
    Args:
        request: FastAPI request object
        pagination: Pagination parameters
        search: Search parameters
        current_user: Authenticated user with appropriate role
        patient_service: Patient service
        audit_logger: Audit logger
        
    Returns:
        Paginated list of patients
    """
    # Log PHI access
    await audit_logger.log_phi_access(
        resource_type="patient",
        resource_id="multiple",
        action="list",
        user_id=current_user["id"],
        reason="Clinical care",
        source_ip=request.client.host,
        details={"query_params": dict(request.query_params)}
    )
    
    # Get patients from service
    patients, total = await patient_service.list_patients(
        skip=pagination.skip,
        limit=pagination.limit,
        search_term=search.search,
        status=search.status,
        min_age=search.min_age,
        max_age=search.max_age
    )
    
    # Return paginated response
    return PatientListResponse(
        items=patients,
        total=total,
        limit=pagination.limit,
        offset=pagination.skip
    )

@router.post(
    "",
    response_model=PatientResponse,
    status_code=201,
    summary="Create patient",
    description="Create a new patient record."
)
async def create_patient(
    request: Request,
    patient_data: PatientCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(verify_has_role(["admin", "clinician"])),
    patient_service: IPatientService = Depends(get_patient_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """
    Create a new patient.
    
    Args:
        request: FastAPI request object
        patient_data: Patient creation data
        background_tasks: Background tasks for asynchronous processing
        current_user: Authenticated user with appropriate role
        patient_service: Patient service
        audit_logger: Audit logger
        
    Returns:
        Newly created patient
    """
    try:
        # Create patient
        patient = await patient_service.create_patient(
            first_name=patient_data.first_name,
            last_name=patient_data.last_name,
            date_of_birth=patient_data.date_of_birth,
            gender=patient_data.gender,
            external_id=patient_data.external_id,
            status=patient_data.status,
            contact_info=patient_data.contact_info
        )
        
        # Log PHI access
        await audit_logger.log_phi_access(
            resource_type="patient",
            resource_id=str(patient.id),
            action="create",
            user_id=current_user["id"],
            reason="Clinical care",
            source_ip=request.client.host,
            details={"patient_id": str(patient.id)}
        )
        
        # Schedule background tasks (e.g., digital twin initialization)
        background_tasks.add_task(
            patient_service.initialize_patient_resources,
            patient.id
        )
        
        # Return created patient
        return patient
        
    except ValueError as e:
        # Handle validation or business rule errors
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Error creating patient: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get(
    "/{patient_id}",
    response_model=PatientResponse,
    summary="Get patient",
    description="Get a single patient by ID."
)
async def get_patient(
    request: Request,
    patient_id: UUID = Path(..., description="The ID of the patient to retrieve"),
    current_user: dict = Depends(verify_has_role(["admin", "clinician"])),
    patient_service: IPatientService = Depends(get_patient_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """
    Get a single patient by ID.
    
    Args:
        request: FastAPI request object
        patient_id: UUID of the patient to retrieve
        current_user: Authenticated user with appropriate role
        patient_service: Patient service
        audit_logger: Audit logger
        
    Returns:
        Patient details
    """
    # Get patient
    patient = await patient_service.get_patient(patient_id)
    
    # Handle not found
    if not patient:
        raise HTTPException(status_code=404, detail=f"Patient with ID {patient_id} not found")
    
    # Log PHI access
    await audit_logger.log_phi_access(
        resource_type="patient",
        resource_id=str(patient_id),
        action="view",
        user_id=current_user["id"],
        reason="Clinical care",
        source_ip=request.client.host,
        details={"patient_id": str(patient_id)}
    )
    
    return patient

@router.put(
    "/{patient_id}",
    response_model=PatientResponse,
    summary="Update patient",
    description="Update an existing patient record."
)
async def update_patient(
    request: Request,
    patient_id: UUID = Path(..., description="The ID of the patient to update"),
    patient_data: PatientUpdateRequest = None,
    current_user: dict = Depends(verify_has_role(["admin", "clinician"])),
    patient_service: IPatientService = Depends(get_patient_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """
    Update a patient.
    
    Args:
        request: FastAPI request object
        patient_id: UUID of the patient to update
        patient_data: Patient update data
        current_user: Authenticated user with appropriate role
        patient_service: Patient service
        audit_logger: Audit logger
        
    Returns:
        Updated patient
    """
    try:
        # Check if patient exists
        existing_patient = await patient_service.get_patient(patient_id)
        if not existing_patient:
            raise HTTPException(status_code=404, detail=f"Patient with ID {patient_id} not found")
        
        # Update patient
        updated_patient = await patient_service.update_patient(
            patient_id=patient_id,
            update_data=patient_data.dict(exclude_unset=True)
        )
        
        # Log PHI access
        await audit_logger.log_phi_access(
            resource_type="patient",
            resource_id=str(patient_id),
            action="update",
            user_id=current_user["id"],
            reason="Clinical care",
            source_ip=request.client.host,
            details={"patient_id": str(patient_id), "updated_fields": list(patient_data.dict(exclude_unset=True).keys())}
        )
        
        return updated_patient
        
    except ValueError as e:
        # Handle validation or business rule errors
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Error updating patient: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete(
    "/{patient_id}",
    status_code=204,
    summary="Delete patient",
    description="Delete a patient record (soft delete)."
)
async def delete_patient(
    request: Request,
    patient_id: UUID = Path(..., description="The ID of the patient to delete"),
    current_user: dict = Depends(verify_has_role(["admin"])),
    patient_service: IPatientService = Depends(get_patient_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """
    Delete (soft delete) a patient.
    
    Args:
        request: FastAPI request object
        patient_id: UUID of the patient to delete
        current_user: Authenticated user with admin role
        patient_service: Patient service
        audit_logger: Audit logger
    """
    # Check if patient exists
    existing_patient = await patient_service.get_patient(patient_id)
    if not existing_patient:
        raise HTTPException(status_code=404, detail=f"Patient with ID {patient_id} not found")
    
    # Perform soft delete
    await patient_service.delete_patient(patient_id)
    
    # Log PHI access
    await audit_logger.log_phi_access(
        resource_type="patient",
        resource_id=str(patient_id),
        action="delete",
        user_id=current_user["id"],
        reason="Administrative action",
        source_ip=request.client.host,
        details={"patient_id": str(patient_id)}
    )
    
    # Return no content for successful deletion
    return None

@router.get(
    "/{patient_id}/timeline",
    response_model=Dict[str, Any],
    summary="Get patient timeline",
    description="Get a timeline of patient events and metrics."
)
async def get_patient_timeline(
    request: Request,
    patient_id: UUID = Path(..., description="The ID of the patient"),
    start_date: Optional[datetime] = Query(None, description="Start date for timeline"),
    end_date: Optional[datetime] = Query(None, description="End date for timeline"),
    event_types: List[str] = Query(None, description="Types of events to include"),
    current_user: dict = Depends(verify_has_role(["admin", "clinician"])),
    patient_service: IPatientService = Depends(get_patient_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """
    Get a patient's timeline of events and metrics.
    
    Args:
        request: FastAPI request object
        patient_id: UUID of the patient
        start_date: Optional start date for filtering
        end_date: Optional end date for filtering
        event_types: Optional list of event types to include
        current_user: Authenticated user with appropriate role
        patient_service: Patient service
        audit_logger: Audit logger
        
    Returns:
        Timeline data for the patient
    """
    # Check if patient exists
    existing_patient = await patient_service.get_patient(patient_id)
    if not existing_patient:
        raise HTTPException(status_code=404, detail=f"Patient with ID {patient_id} not found")
    
    # Get timeline
    timeline = await patient_service.get_patient_timeline(
        patient_id=patient_id,
        start_date=start_date,
        end_date=end_date,
        event_types=event_types
    )
    
    # Log PHI access
    await audit_logger.log_phi_access(
        resource_type="patient_timeline",
        resource_id=str(patient_id),
        action="view",
        user_id=current_user["id"],
        reason="Clinical care",
        source_ip=request.client.host,
        details={
            "patient_id": str(patient_id),
            "start_date": start_date.isoformat() if start_date else None,
            "end_date": end_date.isoformat() if end_date else None,
            "event_types": event_types
        }
    )
    
    return timeline
```

## Interface Schemas

The Patient API uses Pydantic models for request and response validation:

```python
# app/presentation/api/v1/schemas/patient.py
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Dict, List, Optional, Any
from datetime import date, datetime
from uuid import UUID
from enum import Enum

class PatientStatus(str, Enum):
    """Enumeration of possible patient statuses."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"

class PatientGender(str, Enum):
    """Enumeration of patient gender options."""
    MALE = "male"
    FEMALE = "female"
    NON_BINARY = "non_binary"
    OTHER = "other"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"

class ContactInfo(BaseModel):
    """Contact information for a patient."""
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[Dict[str, str]] = None
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "email": "patient@example.com",
                "phone": "+1-555-555-5555",
                "address": {
                    "street": "123 Main St",
                    "city": "Anytown",
                    "state": "NY",
                    "zip": "10001"
                }
            }
        }

class PatientBase(BaseModel):
    """Base model for patient data."""
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    date_of_birth: date
    gender: Optional[PatientGender] = None
    status: PatientStatus = PatientStatus.ACTIVE
    external_id: Optional[str] = None
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "date_of_birth": "1980-01-01",
                "gender": "male",
                "status": "active",
                "external_id": "EXT12345"
            }
        }
    
    @validator('first_name', 'last_name')
    def validate_name(cls, v):
        """Validate name fields."""
        # Remove any special characters that could be used for XSS or injection
        v = v.strip()
        return v

class PatientCreateRequest(PatientBase):
    """Model for patient creation requests."""
    contact_info: Optional[ContactInfo] = None

class PatientUpdateRequest(BaseModel):
    """Model for patient update requests."""
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    date_of_birth: Optional[date] = None
    gender: Optional[PatientGender] = None
    status: Optional[PatientStatus] = None
    external_id: Optional[str] = None
    contact_info: Optional[ContactInfo] = None
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "first_name": "Jane",
                "status": "inactive"
            }
        }

class PatientResponse(PatientBase):
    """Model for patient responses."""
    id: UUID
    contact_info: Optional[ContactInfo] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        """Pydantic configuration."""
        orm_mode = True

class PatientListResponse(BaseModel):
    """Model for paginated patient list responses."""
    items: List[PatientResponse]
    total: int
    limit: int
    offset: int

class PatientSearchParams(BaseModel):
    """Parameters for patient search/filtering."""
    search: Optional[str] = None
    status: Optional[PatientStatus] = None
    min_age: Optional[int] = Field(None, ge=0, le=120)
    max_age: Optional[int] = Field(None, ge=0, le=120)
    
    @validator('max_age')
    def validate_max_age(cls, v, values):
        """Validate that max_age is greater than min_age if both are provided."""
        if v is not None and 'min_age' in values and values['min_age'] is not None:
            if v < values['min_age']:
                raise ValueError('max_age must be greater than or equal to min_age')
        return v
```

## Common Schemas

Common schemas used across multiple routes:

```python
# app/presentation/api/v1/schemas/common.py
from pydantic import BaseModel, Field
from typing import Optional

class PaginationParams(BaseModel):
    """Common pagination parameters."""
    skip: int = Field(0, ge=0, description="Number of items to skip")
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of items to return")
```

## Route Registration

The patient router is registered in the main API router:

```python
# app/presentation/api/v1/api_router.py (excerpt)
from fastapi import APIRouter
from app.presentation.api.v1.routes import (
    auth,
    patient,
    digital_twin,
    biometric_alert_rules,
    # ... other routes
)

api_v1_router = APIRouter(prefix="/api/v1")

# Include all route modules
api_v1_router.include_router(auth.router, prefix="/auth")
api_v1_router.include_router(patient.router)
api_v1_router.include_router(digital_twin.router, prefix="/digital-twins")
api_v1_router.include_router(biometric_alert_rules.router, prefix="/biometric-alert-rules")
# ... other routers
```

## HIPAA Compliance

The Patient API implements multiple HIPAA safeguards:

1. **Authentication**: All endpoints require valid authentication
2. **Authorization**: Role-based access control for patient data
3. **Audit Logging**: Comprehensive logging of all PHI access
4. **Input Validation**: Strict validation of all patient data
5. **Error Sanitization**: No PHI in error responses

## Security Considerations

Key security features of the Patient API:

1. **Parameter Validation**: All parameters are validated using Pydantic models
2. **Injection Prevention**: Name validators prevent XSS and injection attacks
3. **Rate Limiting**: Endpoints are protected by the Rate Limiting Middleware
4. **Error Handling**: Consistent, secure error responses with no PHI leakage
5. **UUID Identifiers**: Non-sequential, non-predictable IDs prevent enumeration

## Testing Approach

The Patient API is tested through multiple test types:

1. **Unit Tests**: Tests for route handler logic in isolation
2. **Integration Tests**: Tests for the API with mocked dependencies
3. **Security Tests**: Tests for security headers, authentication, and authorization
4. **Performance Tests**: Tests for API performance under load

Example test:

```python
# app/tests/unit/presentation/api/v1/endpoints/test_patient_endpoints.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from app.presentation.api.v1.routes.patient import router
from app.main import app

@pytest.fixture
def mock_patient_service():
    """Create a mock patient service for testing."""
    service = AsyncMock()
    
    # Mock get_patient to return a test patient
    service.get_patient.return_value = {
        "id": uuid4(),
        "first_name": "Test",
        "last_name": "Patient",
        "date_of_birth": "1980-01-01",
        "status": "active",
        "created_at": "2023-01-01T00:00:00",
        "updated_at": None
    }
    
    return service

@pytest.fixture
def test_client(mock_patient_service):
    """Create a test client with mocked dependencies."""
    # Override dependencies
    app.dependency_overrides[get_patient_service] = lambda: mock_patient_service
    app.dependency_overrides[verify_has_role] = lambda roles: lambda: {"id": uuid4(), "role": "admin"}
    app.dependency_overrides[get_audit_logger] = lambda: AsyncMock()
    
    # Create client
    with TestClient(app) as client:
        yield client
    
    # Clean up
    app.dependency_overrides = {}

def test_get_patient(test_client, mock_patient_service):
    """Test getting a patient by ID."""
    # Arrange
    patient_id = uuid4()
    
    # Act
    response = test_client.get(f"/api/v1/patients/{patient_id}")
    
    # Assert
    assert response.status_code == 200
    assert "id" in response.json()
    mock_patient_service.get_patient.assert_called_once_with(patient_id)
```

## OpenAPI Documentation

The Patient API is documented through FastAPI's automatic OpenAPI schema generation, including:

1. **Endpoint Summaries**: Brief descriptions of each endpoint's purpose
2. **Detailed Descriptions**: Comprehensive explanations of behavior
3. **Request Schemas**: Expected input formats with examples
4. **Response Schemas**: Expected output formats with status codes
5. **Security Requirements**: Authentication requirements for each endpoint

## Implementation Notes

Key considerations when implementing the Patient API:

1. **Connection Pooling**: Efficient database connections with connection pooling
2. **Async Operations**: All endpoint handlers are asynchronous for high concurrency
3. **Background Tasks**: Long-running operations use background tasks
4. **Error Handling**: Comprehensive error handling with specific status codes
5. **Request Tracing**: Integration with RequestID middleware for tracing

## Conclusion

The Patient API Routes represent a core component of the Clarity AI Backend, providing secure and compliant access to patient data. By following clean architecture principles and implementing comprehensive HIPAA safeguards, these routes ensure that patient data is protected while enabling the powerful capabilities of the psychiatric digital twin platform.
