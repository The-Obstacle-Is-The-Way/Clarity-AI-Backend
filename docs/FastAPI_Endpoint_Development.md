# FastAPI Endpoint Development Guide

This guide outlines the process for developing new API endpoints in the Clarity AI Backend, ensuring they conform to the project's clean architecture, security requirements, and testing standards.

## Endpoint Development Process

### 1. Define Domain Models and Interfaces

Start by defining or extending the necessary domain models and interfaces:

```python
# app/domain/entities/patient.py
from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime
from typing import Optional

class Patient(BaseModel):
    id: UUID
    first_name: str
    last_name: str
    date_of_birth: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True

# app/domain/repositories/patient_repository.py
from abc import ABC, abstractmethod
from uuid import UUID
from typing import List, Optional
from app.domain.entities.patient import Patient

class PatientRepositoryInterface(ABC):
    @abstractmethod
    async def get_by_id(self, patient_id: UUID) -> Optional[Patient]:
        pass
    
    @abstractmethod  
    async def list_patients(self, limit: int, offset: int) -> List[Patient]:
        pass
    
    @abstractmethod
    async def create(self, patient: Patient) -> Patient:
        pass
```

### 2. Implement Repository

Create the concrete repository implementation in the infrastructure layer:

```python
# app/infrastructure/persistence/sqlalchemy/repositories/patient_repository.py
from uuid import UUID
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.domain.repositories.patient_repository import PatientRepositoryInterface
from app.domain.entities.patient import Patient
from app.infrastructure.persistence.sqlalchemy.models.patient import PatientModel

class SQLAlchemyPatientRepository(PatientRepositoryInterface):
    def __init__(self, session: AsyncSession):
        self._session = session
    
    async def get_by_id(self, patient_id: UUID) -> Optional[Patient]:
        result = await self._session.execute(
            select(PatientModel).where(PatientModel.id == patient_id)
        )
        patient_model = result.scalars().first()
        
        if not patient_model:
            return None
            
        return Patient.from_orm(patient_model)
        
    async def list_patients(self, limit: int, offset: int) -> List[Patient]:
        result = await self._session.execute(
            select(PatientModel).limit(limit).offset(offset)
        )
        patient_models = result.scalars().all()
        
        return [Patient.from_orm(model) for model in patient_models]
        
    async def create(self, patient: Patient) -> Patient:
        patient_model = PatientModel(**patient.dict())
        self._session.add(patient_model)
        await self._session.commit()
        await self._session.refresh(patient_model)
        
        return Patient.from_orm(patient_model)
```

### 3. Define Use Cases in Application Layer

Create use cases that orchestrate the domain logic:

```python
# app/application/use_cases/patient_use_cases.py
from uuid import UUID
from typing import List, Optional
from app.domain.entities.patient import Patient
from app.domain.repositories.patient_repository import PatientRepositoryInterface

class PatientUseCase:
    def __init__(self, patient_repository: PatientRepositoryInterface):
        self._patient_repository = patient_repository
    
    async def get_patient(self, patient_id: UUID) -> Optional[Patient]:
        return await self._patient_repository.get_by_id(patient_id)
    
    async def list_patients(self, limit: int = 100, offset: int = 0) -> List[Patient]:
        return await self._patient_repository.list_patients(limit, offset)
    
    async def create_patient(self, patient: Patient) -> Patient:
        # Add any business rules or validation here
        return await self._patient_repository.create(patient)
```

### 4. Create Request/Response Models

Define Pydantic models for requests and responses:

```python
# app/presentation/api/v1/schemas/patient.py
from pydantic import BaseModel, Field, validator
from uuid import UUID
from datetime import datetime
from typing import Optional, List

class PatientCreate(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    date_of_birth: datetime
    
    # Validators to ensure PHI is properly sanitized/validated
    @validator('first_name', 'last_name')
    def validate_name(cls, v):
        # Remove any potential XSS or injection characters
        return v.strip()

class PatientResponse(BaseModel):
    id: UUID
    first_name: str
    last_name: str
    date_of_birth: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None

class PatientListResponse(BaseModel):
    items: List[PatientResponse]
    total: int
    limit: int
    offset: int
```

### 5. Create Dependency Providers

Define provider functions for dependency injection:

```python
# app/presentation/api/v1/dependencies/patient.py
from typing import Annotated
from fastapi import Depends

from app.infrastructure.persistence.sqlalchemy.database import get_session
from app.domain.repositories.patient_repository import PatientRepositoryInterface
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import SQLAlchemyPatientRepository
from app.application.use_cases.patient_use_cases import PatientUseCase
from app.presentation.dependencies.auth import get_current_user
from app.domain.entities.user import User

async def get_patient_repository(session=Depends(get_session)) -> PatientRepositoryInterface:
    return SQLAlchemyPatientRepository(session)

async def get_patient_use_case(
    repository=Depends(get_patient_repository)
) -> PatientUseCase:
    return PatientUseCase(repository)

# Create type aliases for commonly used dependencies
PatientUseCaseDep = Annotated[PatientUseCase, Depends(get_patient_use_case)]
CurrentUserDep = Annotated[User, Depends(get_current_user)]
```

### 6. Implement API Endpoints

Create the actual FastAPI router and endpoints:

```python
# app/presentation/api/v1/routes/patient.py
from fastapi import APIRouter, HTTPException, status, Query, Path
from uuid import UUID
from typing import List

from app.presentation.api.v1.schemas.patient import (
    PatientCreate, 
    PatientResponse,
    PatientListResponse
)
from app.presentation.api.v1.dependencies.patient import PatientUseCaseDep, CurrentUserDep
from app.domain.entities.patient import Patient
from app.domain.exceptions import NotFoundError, PermissionError
from datetime import datetime

router = APIRouter()

@router.get("/{patient_id}", response_model=PatientResponse)
async def get_patient(
    patient_id: UUID = Path(..., description="The patient ID"),
    patient_use_case: PatientUseCaseDep = None,
    current_user: CurrentUserDep = None
) -> PatientResponse:
    """
    Get a patient by ID.
    
    Requires authentication and appropriate permissions.
    """
    try:
        # Check permissions (example)
        if not current_user.can_access_patient(patient_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this patient"
            )
        
        patient = await patient_use_case.get_patient(patient_id)
        
        if not patient:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Patient with ID {patient_id} not found"
            )
            
        return PatientResponse.from_orm(patient)
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patient with ID {patient_id} not found"
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except Exception as e:
        # Log the error but don't expose details to client
        # logger.error(f"Error getting patient {patient_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving the patient"
        )

@router.get("/", response_model=PatientListResponse)
async def list_patients(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    patient_use_case: PatientUseCaseDep = None,
    current_user: CurrentUserDep = None
) -> PatientListResponse:
    """
    List patients with pagination.
    
    Requires authentication and appropriate permissions.
    """
    # Permission check example
    if not current_user.has_role("clinician"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only clinicians can list patients"
        )
    
    patients = await patient_use_case.list_patients(limit, offset)
    total = len(patients)  # In a real app, get actual count
    
    return PatientListResponse(
        items=patients,
        total=total,
        limit=limit,
        offset=offset
    )

@router.post("/", response_model=PatientResponse, status_code=status.HTTP_201_CREATED)
async def create_patient(
    patient_data: PatientCreate,
    patient_use_case: PatientUseCaseDep = None,
    current_user: CurrentUserDep = None
) -> PatientResponse:
    """
    Create a new patient.
    
    Requires authentication and appropriate permissions.
    """
    # Permission check
    if not current_user.has_role("clinician"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only clinicians can create patients"
        )
    
    # Convert to domain entity
    new_patient = Patient(
        id=UUID.uuid4(),
        first_name=patient_data.first_name,
        last_name=patient_data.last_name,
        date_of_birth=patient_data.date_of_birth,
        created_at=datetime.utcnow()
    )
    
    created_patient = await patient_use_case.create_patient(new_patient)
    
    return PatientResponse.from_orm(created_patient)
```

### 7. Register the Router

Add your router to the main API router:

```python
# app/presentation/api/v1/api_router.py
from fastapi import APIRouter
from app.presentation.api/v1/routes.patient import router as patient_router

api_v1_router = APIRouter()

# Other routers...
api_v1_router.include_router(patient_router, prefix="/patients", tags=["patients"])
```

## HIPAA Compliance Considerations

When developing new endpoints, ensure they meet these HIPAA requirements:

1. **No PHI in URLs**: Patient identifiers should use UUIDs, not MRNs or names
2. **Input Validation**: Thoroughly validate all inputs using Pydantic
3. **Access Control**: Verify user permissions before returning any PHI
4. **Error Handling**: Ensure no PHI is leaked in error responses
5. **Audit Logging**: Log all PHI access for compliance
6. **Rate Limiting**: Protect endpoints against brute force attacks
7. **Response Sanitization**: Remove any sensitive fields from responses

Example audit logging integration:

```python
from app.infrastructure.security.audit.service import get_audit_service

@router.get("/{patient_id}", response_model=PatientResponse)
async def get_patient(
    patient_id: UUID,
    patient_use_case: PatientUseCaseDep,
    current_user: CurrentUserDep,
    audit_service = Depends(get_audit_service)
):
    # Record the PHI access
    await audit_service.record_access(
        user_id=current_user.id,
        action="patient_access",
        resource_type="patient",
        resource_id=str(patient_id)
    )
    
    # Endpoint implementation...
```

## Testing New Endpoints

For each new endpoint, create these types of tests:

### 1. Unit Tests

```python
# app/tests/unit/api/v1/routes/test_patient.py
import pytest
from unittest.mock import AsyncMock
from uuid import uuid4
from datetime import datetime
from fastapi import status

from app.domain.entities.patient import Patient

@pytest.mark.asyncio
async def test_get_patient_success(client, mock_patient_use_case):
    # Arrange
    patient_id = uuid4()
    mock_patient = Patient(
        id=patient_id,
        first_name="John",
        last_name="Doe",
        date_of_birth=datetime(1980, 1, 1),
        created_at=datetime.utcnow()
    )
    
    # Set up mock to return our test patient
    mock_patient_use_case.get_patient = AsyncMock(return_value=mock_patient)
    
    # Act
    response = await client.get(f"/api/v1/patients/{patient_id}")
    
    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == str(patient_id)
    assert data["first_name"] == "John"
    assert data["last_name"] == "Doe"
```

### 2. Integration Tests

```python
# app/tests/integration/api/v1/routes/test_patient_integration.py
import pytest
from uuid import uuid4
from fastapi import status
from datetime import datetime

@pytest.mark.asyncio
async def test_patient_create_and_get(authenticated_client, db_session):
    # Create test patient
    patient_data = {
        "first_name": "Jane",
        "last_name": "Smith",
        "date_of_birth": datetime(1985, 5, 15).isoformat()
    }
    
    # Create the patient
    create_response = await authenticated_client.post(
        "/api/v1/patients/",
        json=patient_data
    )
    
    assert create_response.status_code == status.HTTP_201_CREATED
    created_data = create_response.json()
    patient_id = created_data["id"]
    
    # Retrieve the patient
    get_response = await authenticated_client.get(f"/api/v1/patients/{patient_id}")
    
    assert get_response.status_code == status.HTTP_200_OK
    retrieved_data = get_response.json()
    
    # Verify data matches
    assert retrieved_data["first_name"] == patient_data["first_name"]
    assert retrieved_data["last_name"] == patient_data["last_name"]
```

## Common Patterns and Best Practices

### 1. Error Handling

Follow this pattern for consistent error handling:

```python
try:
    # Business logic
    result = await service.perform_operation()
    return result
except NotFoundError as e:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=str(e)
    )
except PermissionError as e:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=str(e)
    )
except ValidationError as e:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(e)
    )
except Exception as e:
    # Log the error with full details for internal tracking
    logger.error(f"Error in endpoint: {str(e)}", exc_info=True)
    # Return a sanitized error to the client
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An unexpected error occurred"
    )
```

### 2. Pagination

For endpoints returning collections:

```python
@router.get("/", response_model=ListResponse)
async def list_resources(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    # Other filters
):
    items = await service.list_items(limit, offset)
    total = await service.count_items()
    
    return ListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset
    )
```

### 3. Query Parameter Filtering

For endpoints with complex filtering:

```python
@router.get("/", response_model=ListResponse)
async def list_resources(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    created_after: Optional[datetime] = Query(None),
    search: Optional[str] = Query(None)
):
    filters = {
        "status": status,
        "created_after": created_after,
        "search": search
    }
    
    # Remove None values
    filters = {k: v for k, v in filters.items() if v is not None}
    
    items = await service.list_items(limit, offset, filters)
    total = await service.count_items(filters)
    
    return ListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset
    )
```

## Conclusion

Following these guidelines ensures your endpoints:

1. Adhere to clean architecture principles
2. Maintain proper separation of concerns
3. Follow HIPAA security requirements
4. Are thoroughly tested
5. Have consistent error handling
6. Perform efficiently

Remember that all API endpoints should be documented in OpenAPI, include appropriate status codes, and have comprehensive test coverage before being merged into the main codebase. 