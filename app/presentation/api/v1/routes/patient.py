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

# Placeholder dependency - replace with actual service implementation later
def get_patient_service(
    db_session: AsyncSession = Depends(get_db)
) -> PatientService:
    """Dependency provider for PatientService."""
    repo = SQLPatientRepoImpl(db_session=db_session) 
    return PatientService(repository=repo) 

logger = logging.getLogger(__name__)

router = APIRouter()

# MODIFIED: Remove the local mock dependency function
# async def mock_get_current_user_for_route() -> DomainUser:
#     return DomainUser(
#         id=uuid.uuid4(),
#         email="route_mock_user@example.com",
#         username="route_mock_user",
#         full_name="Route Mock User",
#         password_hash="somehash",
#         roles={UserRole.ADMIN},
#         status=UserStatus.ACTIVE
#     )

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
    current_user: DomainUser = Depends(CurrentUserDep),
    # Make query parameters truly optional with explicit defaults
    args: Optional[str] = Query(default=None, description="Optional arguments (for backward compatibility)"),
    kwargs: Optional[str] = Query(default=None, description="Optional keyword arguments (for backward compatibility)")
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

# Add other routes (PUT, DELETE, LIST) later

# @router.put(
#     "/{patient_id}", 
#     response_model=PatientRead, 
#     name="patients:update_patient",
#     summary="Update an existing patient",
#     dependencies=[Depends(require_roles([UserRole.ADMIN, UserRole.CLINICIAN]))]
# )
# async def update_patient(
#     patient_id: UUID, 
#     patient_update_data: PatientUpdateRequest, # COMMENTED OUT TEMPORARILY
#     service: PatientService = Depends(get_patient_service),
#     # current_user: CurrentUserDep = Depends(get_current_user) # Authorization handled by require_roles
# ) -> PatientRead:
#     logger.info(f"Endpoint update_patient called for patient_id: {patient_id}")
#     updated_patient = await service.update_patient(patient_id, patient_update_data)
#     if updated_patient is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")
#     return updated_patient
