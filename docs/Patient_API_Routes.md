# Patient API Routes

## Overview

The Patient API Routes are a foundational component of the Clarity AI Backend that provide access to patient data and operations. These routes represent the RESTful interface for patient management within the psychiatric digital twin platform, with a current focus on patient creation and retrieval operations, incorporating comprehensive HIPAA safeguards.

## Implementation Status

> ⚠️ **IMPORTANT**: There are significant discrepancies between this documentation and the actual implementation in the codebase:

| Component | Documentation Status | Implementation Status | Notes |
|-----------|---------------------|----------------------|-------|
| GET /{patient_id} | ✅ Documented | ✅ Implemented | Using dependency injection to validate patient ID |
| POST / (Create) | ✅ Documented | ✅ Implemented | Implementation matches documentation |
| PUT /{patient_id} | ✅ Documented | ❌ Commented Out | Update operation is commented out in code |
| DELETE /{patient_id} | ✅ Documented | ❌ Not Implemented | Delete operation doesn't exist in code |
| GET / (List Patients) | ✅ Documented | ❌ Not Implemented | List operation doesn't exist in code |
| GET /{patient_id}/timeline | ✅ Documented | ❌ Not Implemented | Timeline operation doesn't exist in code |
| Schema Validation | ✅ Documented | ⚠️ Partial Mismatch | Schemas in code differ from documented schemas |
| Security Features | ✅ Documented | ⚠️ Partially Implemented | Role-based access exists but audit logging is missing |

### Current Implementation Gaps

1. **Missing Endpoints**: Several documented endpoints (PUT, DELETE, LIST) are either commented out or not implemented
2. **Schema Mismatch**: The actual schema implementation is much simpler than documented
3. **Missing Audit Logging**: The comprehensive audit logging described is not implemented
4. **Incomplete Service Implementation**: The service contains placeholder code and incomplete functionality

## Clean Architecture Context

The Patient API Routes implement the presentation layer within the clean architecture framework:

1. **Routes**: Define HTTP endpoints and handle request/response transformations
2. **Dependencies**: Inject required services through FastAPI's dependency system
3. **Schemas**: Validate input and output data using Pydantic models
4. **Authentication**: Ensure proper authorization for PHI access

## Actual Route Implementation

The Patient API routes are defined in `app/presentation/api/v1/routes/patient.py` with the following implemented endpoints:

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

@router.get(
    "/{patient_id}",
    response_model=PatientRead,
    name="patients:read_patient",
    summary="Get a specific patient by ID",
    description="Retrieve detailed information about a specific patient using their UUID.",
    tags=["Patients"],
)
async def read_patient(
    patient_domain_entity: Patient = Depends(get_validated_patient_id_for_read),
    service: PatientService = Depends(get_patient_service)
) -> PatientRead:
    """
    Retrieve a patient by their ID.
    The actual patient object is already fetched and authorized by the dependency.
    """
    logger.info(f"Endpoint read_patient: Returning data for patient {patient_domain_entity.id}")
    return PatientRead.model_validate(patient_domain_entity)

@router.post(
    "/",
    response_model=PatientCreateResponse, 
    status_code=status.HTTP_201_CREATED, 
    summary="Create Patient",
    description="Create a new patient record."
)
async def create_patient_endpoint(
    patient_data: PatientCreateRequest, 
    service: PatientService = Depends(get_patient_service),
    current_user: DomainUser = Depends(CurrentUserDep)
) -> PatientCreateResponse: 
    """Create a new patient."""
    logger.info(f"User {current_user.id} attempting to create patient: {patient_data.first_name} {patient_data.last_name}")
    try:
        created_patient = await service.create_patient(patient_data, created_by_id=current_user.id)
        return created_patient
    except Exception as e:
        logger.error(f"Error creating patient by user {current_user.id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while creating the patient."
        ) from e

# Update operation is commented out in the actual code
# @router.put(
#     "/{patient_id}", 
#     response_model=PatientRead, 
#     name="patients:update_patient",
#     summary="Update an existing patient"
# )
```

## Actual Schema Implementation

The actual schema implementation is much simpler than documented:

```python
import uuid
from datetime import date, datetime
from pydantic import BaseModel, Field, EmailStr, computed_field, ConfigDict

class PatientBase(BaseModel):
    first_name: str = Field(..., description="Patient's first name")
    last_name: str = Field(..., description="Patient's last name")
    date_of_birth: date = Field(..., description="Patient's date of birth")
    email: EmailStr | None = Field(None, description="Patient's email address")
    phone_number: str | None = Field(None, description="Patient's phone number")

class PatientCreateRequest(PatientBase):
    # Fields specific to creation, if any. For now, inherits all from PatientBase.
    pass

class PatientRead(PatientBase):
    id: uuid.UUID = Field(..., description="Unique identifier for the patient")
    created_at: datetime | None = Field(None, description="When the patient record was created")
    updated_at: datetime | None = Field(None, description="When the patient record was last updated")
    created_by: uuid.UUID | None = Field(None, description="ID of the user who created the patient record")

    @computed_field
    @property
    def name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    model_config = ConfigDict(from_attributes=True)

# Create a specific response for patient creation
class PatientCreateResponse(PatientRead):
    """Response model for patient creation endpoint."""
    created_at: datetime = Field(..., description="When the patient record was created")
    updated_at: datetime = Field(..., description="When the patient record was last updated")
    created_by: uuid.UUID = Field(..., description="ID of the user who created the patient record")
```

## Service Implementation 

The current service implementation contains placeholder code and is incomplete:

```python
class PatientService:
    """Placeholder for Patient Service logic."""
    def __init__(self, repository: PatientRepository):
        self.repo = repository

    async def get_patient_by_id(self, patient_id: str) -> dict[str, str] | None:
        """Retrieves a patient by ID.

        Note: Authentication/Authorization context temporarily removed for basic tests.
        Needs to be added back later.
        """
        logger.debug(f"Service: Fetching patient {patient_id}")
        # Placeholder - replace with actual repository call and domain object handling
        # patient = await self.repo.get_by_id(uuid.UUID(patient_id))
        # if not patient:
        #     return None
        # return PatientRead.model_validate(patient).model_dump() # Example using Pydantic
        if patient_id == "non-existent-patient": # Simple mock for not found
             return None
        return {"id": patient_id, "name": "Placeholder from Service"}

    async def create_patient(self, patient_data: PatientCreateRequest) -> dict[str, str]:
        """Creates a new patient.

        Placeholder implementation.
        """
        logger.debug(f"Service: Creating patient with name {patient_data.name}")
        # In a real scenario:
        # 1. Map PatientCreateRequest to domain entity (e.g., Patient)
        # 2. Add necessary fields (e.g., generate ID)
        # 3. Call repository's add/create method
        # 4. Map the created domain entity back to PatientRead/Response schema

        # Placeholder response:
        new_id = str(uuid.uuid4())
        created_patient_dict = {
            "id": new_id,
            "name": patient_data.name
        }
        logger.info(f"Service: Simulated creation of patient {new_id}")
        return created_patient_dict
```

## Implementation Roadmap

To address the current implementation gaps, the following tasks are needed:

1. **Complete Service Implementation**
   - Implement the PatientService with full functionality
   - Replace placeholder code with actual repository calls

2. **Add Missing Endpoints**
   - Implement PUT endpoint for patient updates
   - Implement DELETE endpoint for soft-deleting patients
   - Implement GET endpoint for listing patients with filtering and pagination

3. **Schema Alignment**
   - Enhance schemas to match documented functionality
   - Add missing schemas for filtering, sorting, and pagination

4. **Security Enhancements**
   - Implement comprehensive audit logging of PHI access
   - Enhance authentication and authorization checks

## HIPAA Compliance

The Patient API plans to implement multiple HIPAA safeguards, but several are not yet fully implemented:

1. **Authentication**: ✅ All endpoints require valid authentication
2. **Authorization**: ⚠️ Basic role-based access exists but needs enhancement
3. **Audit Logging**: ❌ Comprehensive logging of PHI access is missing
4. **Input Validation**: ✅ Basic validation exists via Pydantic models
5. **Error Sanitization**: ⚠️ Limited error handling with potential for improvement

## Security Considerations

Current security features and needed enhancements:

1. **Parameter Validation**: ✅ Basic validation exists via Pydantic models
2. **Injection Prevention**: ⚠️ Limited protection in current implementation
3. **Rate Limiting**: ❓ Not verified in the current implementation
4. **Error Handling**: ⚠️ Basic error handling exists but needs improvement
5. **UUID Identifiers**: ✅ Using UUID identifiers for patients

## Conclusion

The Patient API Routes currently provide basic functionality for patient creation and retrieval. Significant enhancements are needed to fully implement the documented functionality, especially regarding HIPAA compliance, comprehensive API operations, and security features. The current implementation represents a starting point that should be further developed to meet the requirements of a production-ready psychiatric digital twin platform.
